// SPDX-License-Identifier: Apache-2.0
//! The TLS checks: the runtime's `AJAR_TLS_*` policy table
//! (`ajar_connector_common::nats`), then a live handshake that turns rustls
//! errors into named causes with a fix.

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::{AlertDescription, CertificateError, ClientConfig, RootCertStore, SignatureScheme};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;

use crate::certs::{self, CertInfo};
use crate::net::{self, Endpoint};

const TLS_VARS: [&str; 3] = ["AJAR_TLS_CA", "AJAR_TLS_CERT", "AJAR_TLS_KEY"];

/// The `AJAR_TLS_*` triple as the runtime resolves it: all or none, and
/// whitespace counts as unset.
#[derive(Debug)]
pub enum Policy {
    Mtls {
        ca: String,
        cert: String,
        key: String,
    },
    /// `required` is AJAR_REQUIRE_TLS or a tls:// URL; the runtime then
    /// refuses to start.
    Cleartext { required: bool },
    /// Some but not all set; the runtime refuses to start.
    Partial {
        set: Vec<&'static str>,
        missing: Vec<&'static str>,
    },
}

pub fn policy(url_demands_tls: bool) -> Policy {
    let values = TLS_VARS.map(|name| std::env::var(name).ok().filter(|v| !v.trim().is_empty()));
    match values.clone() {
        [Some(ca), Some(cert), Some(key)] => Policy::Mtls { ca, cert, key },
        [None, None, None] => {
            let require_tls = std::env::var("AJAR_REQUIRE_TLS")
                .map(|v| {
                    let v = v.trim().to_ascii_lowercase();
                    !(v.is_empty() || v == "0" || v == "false" || v == "no")
                })
                .unwrap_or(false);
            Policy::Cleartext {
                required: url_demands_tls || require_tls,
            }
        }
        _ => {
            let (set, missing): (Vec<_>, Vec<_>) =
                TLS_VARS.iter().zip(&values).partition(|(_, v)| v.is_some());
            Policy::Partial {
                set: set.into_iter().map(|(n, _)| *n).collect(),
                missing: missing.into_iter().map(|(n, _)| *n).collect(),
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct Diagnosis {
    pub problem: String,
    pub fix: String,
}

#[derive(Debug)]
pub struct Handshake {
    /// The server's leaf, captured even when verification fails.
    pub server_cert: Option<CertInfo>,
    /// Ok says how far the probe got.
    pub outcome: Result<String, Diagnosis>,
}

/// Records the server's leaf before delegating to webpki, so a failed
/// handshake still shows what the server presented.
#[derive(Debug)]
struct RecordingVerifier {
    inner: Arc<WebPkiServerVerifier>,
    seen: Mutex<Option<CertificateDer<'static>>>,
}

impl ServerCertVerifier for RecordingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        *self.seen.lock().expect("no poisoned lock") = Some(end_entity.clone().into_owned());
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// The full TLS path on a fresh connection: cleartext INFO preflight,
/// handshake under the given CA and client identity, then CONNECT and PING to
/// surface a deferred rejection or an authorization refusal.
pub async fn probe(
    ep: &Endpoint,
    ca_path: &str,
    client: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
    source_id: &str,
    timeout: Duration,
) -> anyhow::Result<Handshake> {
    static CRYPTO_PROVIDER: OnceLock<()> = OnceLock::new();
    CRYPTO_PROVIDER.get_or_init(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });

    let mut roots = RootCertStore::empty();
    for cert in certs::load_pem_certs(ca_path)? {
        roots.add(cert).map_err(|e| {
            anyhow::anyhow!("a certificate in {ca_path} was rejected as a trust root: {e}")
        })?;
    }

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|e| anyhow::anyhow!("building a verifier from {ca_path}: {e}"))?;
    let recorder = Arc::new(RecordingVerifier {
        inner,
        seen: Mutex::new(None),
    });

    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("aws-lc-rs supports the default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(recorder.clone());
    let config = match client {
        Some((chain, key)) => builder.with_client_auth_cert(chain, key).map_err(|e| {
            anyhow::anyhow!(
                "AJAR_TLS_CERT and AJAR_TLS_KEY do not form a usable pair: {e}. \
                 The key file must be the private key for the certificate; \
                 check the two paths are not swapped and belong together"
            )
        })?,
        None => builder.with_no_client_auth(),
    };

    let mut tcp = match net::dial(ep, timeout).await {
        net::Dial::Connected(s) => s,
        net::Dial::NoDns(e) | net::Dial::NoAnswer(e) => {
            return Err(anyhow::anyhow!(
                "could not reconnect for the TLS probe: {e}"
            ))
        }
    };

    // A TLS-first server stays silent; one whose INFO offers no TLS at all
    // will never handshake.
    let greeting = net::read_info(&mut tcp, Duration::from_millis(1500)).await;
    if let Ok(Some(info)) = &greeting {
        if !info.tls_required && !info.tls_available {
            return Ok(Handshake {
                server_cert: None,
                outcome: Err(Diagnosis {
                    problem: format!(
                        "the server at {} is running WITHOUT TLS while this connector is configured for mTLS",
                        ep.addr()
                    ),
                    fix: "This is usually the wrong port or the wrong environment (a dev broker \
                          instead of the operator's ingest endpoint). Check nats_url against the \
                          one in the operator's invite."
                        .into(),
                }),
            });
        }
    }

    let server_name = ServerName::try_from(ep.host.clone())
        .map_err(|_| anyhow::anyhow!("{:?} is not usable as a TLS server name", ep.host))?;
    let connector = TlsConnector::from(Arc::new(config));
    let handshake = tokio::time::timeout(timeout, connector.connect(server_name, tcp)).await;

    let seen = recorder
        .seen
        .lock()
        .expect("no poisoned lock")
        .as_ref()
        .and_then(|der| certs::inspect_der(der.as_ref()).ok());

    let mut tls = match handshake {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            let diagnosis = match e.get_ref().and_then(|i| i.downcast_ref::<rustls::Error>()) {
                Some(rustls_err) => classify_rustls_error(rustls_err, ep, seen.as_ref(), source_id),
                None => Diagnosis {
                    problem: format!("the TLS handshake failed: {e}"),
                    fix: "The error above is not a certificate problem. If the endpoint is not \
                          a NATS server on a TLS port, fix nats_url; otherwise send this exact \
                          message to the operator."
                        .into(),
                },
            };
            return Ok(Handshake {
                server_cert: seen,
                outcome: Err(diagnosis),
            });
        }
        Err(_) => {
            return Ok(Handshake {
                server_cert: seen,
                outcome: Err(Diagnosis {
                    problem: format!("the TLS handshake hung for {}s", timeout.as_secs()),
                    fix: "Something between here and the server is eating the handshake \
                          (a TCP-level proxy or firewall that is not TLS-aware). Ask whoever \
                          owns the network path."
                        .into(),
                }),
            })
        }
    };

    // Under TLS 1.3 a server rejects a client certificate only after the
    // handshake completes, so the PING surfaces it. With authentication on, NATS
    // refuses anything but CONNECT first, and answers a refused identity only
    // after its authorization timeout.
    let connect = format!(
        "CONNECT {{\"verbose\":false,\"pedantic\":false,\"tls_required\":true,\
         \"name\":\"ajar-doctor\",\"lang\":\"rust\",\"version\":\"{}\",\"protocol\":1}}\r\nPING\r\n",
        env!("CARGO_PKG_VERSION")
    );
    let _ = tls.write_all(connect.as_bytes()).await;
    // NATS may send its own PING while it waits on the callout; that one is answered,
    // and the PONG to this PING or an -ERR decides.
    let mut buf = vec![0u8; 4096];
    let mut text = String::new();
    const ANSWER_WAIT: Duration = Duration::from_secs(15);
    let deadline = tokio::time::Instant::now() + ANSWER_WAIT;
    let post = loop {
        match tokio::time::timeout_at(deadline, tls.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {
                text.push_str(&String::from_utf8_lossy(&buf[..n]));
                while let Some(at) = text.find("PING\r\n") {
                    text.replace_range(at..at + 6, "");
                    let _ = tls.write_all(b"PONG\r\n").await;
                }
                if text.contains("-ERR") || text.contains("PONG") {
                    break Ok(Ok(text));
                }
            }
            Ok(Ok(_)) => break Ok(Ok(text)),
            Ok(Err(e)) => break Ok(Err(e)),
            Err(elapsed) => break Err(elapsed),
        }
    };
    let outcome = match post {
        Ok(Ok(text)) if text.trim().is_empty() => Err(Diagnosis {
            problem: "the server closed the connection right after the handshake".into(),
            fix: client_cert_fix(source_id),
        }),
        Ok(Ok(text)) => {
            if text.contains("-ERR") {
                Err(Diagnosis {
                    problem: format!(
                        "TLS is fine, but NATS refused this connector: {}",
                        text.trim()
                    ),
                    fix: format!(
                        "The transport works and the bus refused this identity. On Core, `ajar \
                         status` shows whether {source_id} is invited or revoked."
                    ),
                })
            } else {
                Ok(format!(
                    "TLS established and the server answered ({})",
                    text.lines()
                        .find(|line| !line.trim().is_empty())
                        .unwrap_or("")
                        .trim()
                ))
            }
        }
        Ok(Err(e)) => Err(Diagnosis {
            problem: match e.get_ref().and_then(|i| i.downcast_ref::<rustls::Error>()) {
                Some(rustls::Error::AlertReceived(alert)) => format!(
                    "the server accepted the handshake, then rejected this connector's client \
                     certificate ({alert:?})"
                ),
                _ => format!("the connection failed right after the handshake: {e}"),
            },
            fix: client_cert_fix(source_id),
        }),
        Err(_) => Err(Diagnosis {
            problem: format!(
                "TLS is fine, but the bus did not answer CONNECT within {}s",
                ANSWER_WAIT.as_secs()
            ),
            fix: "The bus waits on Core to admit this connector, and Core did not answer: ask \
                  the operator whether Core is running (`ajar status`)."
                .into(),
        }),
    };

    Ok(Handshake {
        server_cert: seen,
        outcome,
    })
}

/// The onboarding step a rustls error points at.
pub fn classify_rustls_error(
    err: &rustls::Error,
    ep: &Endpoint,
    seen: Option<&CertInfo>,
    source_id: &str,
) -> Diagnosis {
    use rustls::Error as E;
    match err {
        E::InvalidCertificate(ce) => match ce {
            // BadSignature is a root that matches by name but not by key (a
            // re-keyed CA with the same DN): the same wrong CA file.
            CertificateError::UnknownIssuer | CertificateError::BadSignature => Diagnosis {
                problem: "the server's certificate is not signed by the CA in AJAR_TLS_CA".into(),
                fix: "You have the wrong CA file for this endpoint. Get the operator's current \
                      CA bundle (the one that signed the server certificate) and point \
                      AJAR_TLS_CA at it."
                    .into(),
            },
            CertificateError::Expired | CertificateError::ExpiredContext { .. } => {
                let when = seen.map(|c| c.not_after_text.clone()).unwrap_or_default();
                Diagnosis {
                    problem: format!("the server's certificate expired ({when})"),
                    fix: "If that date is in the future on the wall calendar, this machine's \
                          clock is AHEAD; run `date -u` and fix the clock. Otherwise the \
                          operator must renew the server certificate."
                        .into(),
                }
            }
            CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. } => {
                let when = seen.map(|c| c.not_before_text.clone()).unwrap_or_default();
                Diagnosis {
                    problem: format!("the server's certificate is not valid yet (from {when})"),
                    fix: "Either this machine's clock is BEHIND (run `date -u` and compare with \
                          a clock you trust) or the certificate was issued postdated. A skewed \
                          clock also corrupts your event timestamps, so fix it either way."
                        .into(),
                }
            }
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => {
                let names = seen
                    .map(|c| {
                        if c.san.is_empty() {
                            "no names at all (the certificate has no subjectAltName)".to_string()
                        } else {
                            c.san.join(", ")
                        }
                    })
                    .unwrap_or_else(|| "unknown".into());
                Diagnosis {
                    problem: format!(
                        "the server's certificate does not cover {:?}; it covers: {names}",
                        ep.host
                    ),
                    fix: format!(
                        "Connect using a name the certificate lists (change nats_url), or ask \
                         the operator to reissue the server certificate with {:?} in its \
                         subjectAltName. A certificate without any SAN is refused by modern \
                         TLS even when its CN matches.",
                        ep.host
                    ),
                }
            }
            other => Diagnosis {
                problem: format!("the server presented an unusable certificate: {other:?}"),
                fix: "Send this exact message to the operator; the server-side certificate \
                      needs attention."
                    .into(),
            },
        },
        E::AlertReceived(alert) => match alert {
            AlertDescription::BadCertificate
            | AlertDescription::CertificateUnknown
            | AlertDescription::UnknownCA
            | AlertDescription::CertificateRequired
            | AlertDescription::CertificateExpired
            | AlertDescription::AccessDenied
            | AlertDescription::HandshakeFailure => Diagnosis {
                problem: format!(
                    "the server refused this connector's client certificate ({alert:?})"
                ),
                fix: client_cert_fix(source_id),
            },
            other => Diagnosis {
                problem: format!("the server aborted the handshake ({other:?})"),
                fix: "Send this exact message to the operator together with your source_id.".into(),
            },
        },
        other => Diagnosis {
            problem: format!("the TLS handshake failed: {other}"),
            fix: "This is neither a bad server certificate nor a refused client certificate. \
                  Send this exact message to the operator."
                .into(),
        },
    }
}

fn client_cert_fix(source_id: &str) -> String {
    format!(
        "The usual causes, in order: (1) your client certificate is not issued by the CA the \
         server trusts for clients; (2) its CN is not exactly your source_id ({source_id:?}); \
         (3) it has expired. Print yours with \
         `openssl x509 -in \"$AJAR_TLS_CERT\" -noout -subject -dates` and confirm all three \
         with the operator."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep() -> Endpoint {
        Endpoint {
            host: "nats.example.mil".into(),
            port: 4443,
            tls_scheme: true,
        }
    }

    fn cert(san: &[&str]) -> CertInfo {
        CertInfo {
            common_name: None,
            san: san.iter().map(|s| s.to_string()).collect(),
            not_before: 0,
            not_after: 0,
            not_before_text: "Jan 1 00:00:00 2026 +00:00".into(),
            not_after_text: "Jan 1 00:00:00 2027 +00:00".into(),
            is_ca: false,
        }
    }

    #[test]
    fn wrong_ca_names_the_ca_file() {
        let d = classify_rustls_error(
            &rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer),
            &ep(),
            None,
            "acme-radar-1",
        );
        assert!(d.problem.contains("not signed by the CA in AJAR_TLS_CA"));
        assert!(d.fix.contains("CA bundle"));
    }

    #[test]
    fn san_mismatch_lists_covered_names() {
        let d = classify_rustls_error(
            &rustls::Error::InvalidCertificate(CertificateError::NotValidForName),
            &ep(),
            Some(&cert(&["other.name"])),
            "acme-radar-1",
        );
        assert!(d.problem.contains("other.name"));
        assert!(d.fix.contains("subjectAltName"));
    }

    #[test]
    fn san_less_certificate_called_out() {
        let d = classify_rustls_error(
            &rustls::Error::InvalidCertificate(CertificateError::NotValidForName),
            &ep(),
            Some(&cert(&[])),
            "acme-radar-1",
        );
        assert!(d.problem.contains("no subjectAltName"));
    }

    #[test]
    fn expired_certificate_points_at_the_clock() {
        let d = classify_rustls_error(
            &rustls::Error::InvalidCertificate(CertificateError::Expired),
            &ep(),
            Some(&cert(&[])),
            "s",
        );
        assert!(d.fix.contains("date -u"));
    }

    #[test]
    fn not_yet_valid_certificate_points_at_a_slow_clock() {
        let d = classify_rustls_error(
            &rustls::Error::InvalidCertificate(CertificateError::NotValidYet),
            &ep(),
            Some(&cert(&[])),
            "s",
        );
        assert!(d.fix.contains("BEHIND"));
    }

    #[test]
    fn server_alert_blames_client_certificate() {
        let d = classify_rustls_error(
            &rustls::Error::AlertReceived(AlertDescription::BadCertificate),
            &ep(),
            None,
            "acme-radar-1",
        );
        assert!(d.problem.contains("client certificate"));
        assert!(d.fix.contains("acme-radar-1"));
        assert!(d.fix.contains("CN"));
    }

    #[test]
    fn policy_table_matches_the_runtime() {
        // These names are fixed and process-global, so no other unit test sets them.
        let saved: Vec<_> = [
            "AJAR_TLS_CA",
            "AJAR_TLS_CERT",
            "AJAR_TLS_KEY",
            "AJAR_REQUIRE_TLS",
        ]
        .iter()
        .map(|n| (*n, std::env::var(n).ok()))
        .collect();

        for (n, _) in &saved {
            std::env::remove_var(n);
        }
        assert!(matches!(
            policy(false),
            Policy::Cleartext { required: false }
        ));
        assert!(matches!(policy(true), Policy::Cleartext { required: true }));

        std::env::set_var("AJAR_REQUIRE_TLS", "1");
        assert!(matches!(
            policy(false),
            Policy::Cleartext { required: true }
        ));
        std::env::set_var("AJAR_REQUIRE_TLS", "no");
        assert!(matches!(
            policy(false),
            Policy::Cleartext { required: false }
        ));

        std::env::set_var("AJAR_TLS_CA", "/x/ca.pem");
        let p = policy(false);
        match p {
            Policy::Partial { set, missing } => {
                assert_eq!(set, vec!["AJAR_TLS_CA"]);
                assert_eq!(missing, vec!["AJAR_TLS_CERT", "AJAR_TLS_KEY"]);
            }
            other => panic!("expected Partial, got {other:?}"),
        }

        std::env::set_var("AJAR_TLS_CERT", "/x/cert.pem");
        std::env::set_var("AJAR_TLS_KEY", "/x/key.pem");
        assert!(matches!(policy(false), Policy::Mtls { .. }));

        std::env::set_var("AJAR_TLS_KEY", "   ");
        assert!(
            matches!(policy(false), Policy::Partial { .. }),
            "whitespace counts as unset"
        );

        for (n, v) in saved {
            match v {
                Some(v) => std::env::set_var(n, v),
                None => std::env::remove_var(n),
            }
        }
    }
}
