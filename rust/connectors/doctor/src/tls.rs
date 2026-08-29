// SPDX-License-Identifier: Apache-2.0
//! The TLS half of the doctor: the same fail-closed policy table the runtime
//! applies (`ajar_connector_common::nats`), then a live handshake that turns
//! rustls errors into named causes with a fix.

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use anyhow::anyhow;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::{AlertDescription, CertificateError, ClientConfig, RootCertStore, SignatureScheme};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;

use crate::certs::{self, CertInfo};
use crate::net::{self, Endpoint};

/// Which of the `AJAR_TLS_*` triple is set, resolved exactly the way the
/// runtime resolves it (all-or-none, whitespace is unset).
#[derive(Debug)]
pub enum Policy {
    /// All three set: mTLS, the production path.
    Mtls {
        ca: String,
        cert: String,
        key: String,
    },
    /// None set. `required` mirrors AJAR_REQUIRE_TLS / a tls:// URL; when it
    /// is true the runtime refuses to start, so the doctor fails the same way.
    Cleartext { required: bool },
    /// Some but not all set: the runtime refuses to guess, and so do we.
    Partial {
        set: Vec<&'static str>,
        missing: Vec<&'static str>,
    },
}

/// Read the policy from the environment, given whether the URL demands TLS.
pub fn policy(url_demands_tls: bool) -> Policy {
    let vars = [
        ("AJAR_TLS_CA", non_empty_env("AJAR_TLS_CA")),
        ("AJAR_TLS_CERT", non_empty_env("AJAR_TLS_CERT")),
        ("AJAR_TLS_KEY", non_empty_env("AJAR_TLS_KEY")),
    ];
    let set: Vec<_> = vars.iter().filter(|(_, v)| v.is_some()).collect();
    match set.len() {
        3 => Policy::Mtls {
            ca: vars[0].1.clone().expect("checked"),
            cert: vars[1].1.clone().expect("checked"),
            key: vars[2].1.clone().expect("checked"),
        },
        0 => Policy::Cleartext {
            required: url_demands_tls || require_tls_flag(),
        },
        _ => Policy::Partial {
            set: vars
                .iter()
                .filter(|(_, v)| v.is_some())
                .map(|(n, _)| *n)
                .collect(),
            missing: vars
                .iter()
                .filter(|(_, v)| v.is_none())
                .map(|(n, _)| *n)
                .collect(),
        },
    }
}

fn require_tls_flag() -> bool {
    std::env::var("AJAR_REQUIRE_TLS")
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            !(v.is_empty() || v == "0" || v == "false" || v == "no")
        })
        .unwrap_or(false)
}

fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

/// A named cause with its remedy, ready for the report.
#[derive(Debug, Clone)]
pub struct Diagnosis {
    pub problem: String,
    pub fix: String,
}

/// What the live handshake established.
#[derive(Debug)]
pub struct Handshake {
    /// The server's leaf certificate, captured even when verification fails,
    /// so the clock check and the name lists work on the failure path too.
    pub server_cert: Option<CertInfo>,
    /// Ok carries a plain-words description of how far we got.
    pub outcome: Result<String, Diagnosis>,
}

/// Records the server's leaf before delegating to the real webpki verifier,
/// so a failed handshake still tells us what the server presented.
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

fn install_crypto_provider() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Attempt the full TLS path against a fresh connection: cleartext INFO
/// preflight, handshake under the given CA and client identity, then a PING
/// to force any deferred rejection into the open. Never publishes anything.
pub async fn probe(
    ep: &Endpoint,
    ca_path: &str,
    client: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
    source_id: &str,
    timeout: Duration,
) -> anyhow::Result<Handshake> {
    install_crypto_provider();

    let mut roots = RootCertStore::empty();
    for cert in certs::load_pem_certs(ca_path)? {
        roots
            .add(cert)
            .map_err(|e| anyhow!("a certificate in {ca_path} was rejected as a trust root: {e}"))?;
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|e| anyhow!("building a verifier from {ca_path}: {e}"))?;
    let recorder = Arc::new(RecordingVerifier {
        inner,
        seen: Mutex::new(None),
    });

    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring supports the default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(recorder.clone());
    let config = match client {
        Some((chain, key)) => builder.with_client_auth_cert(chain, key).map_err(|e| {
            anyhow!(
                "AJAR_TLS_CERT and AJAR_TLS_KEY do not form a usable pair: {e}. \
                 The key file must be the private key for the certificate; \
                 check the two paths are not swapped and belong together"
            )
        })?,
        None => builder.with_no_client_auth(),
    };

    // Fresh connection for the probe.
    let mut tcp = match net::dial(ep, timeout).await {
        net::Dial::Connected(s) => s,
        net::Dial::NoDns(e) | net::Dial::NoAnswer(e) => {
            return Err(anyhow!("could not reconnect for the TLS probe: {e}"))
        }
    };

    // Standard NATS speaks INFO in cleartext before the upgrade; TLS-first
    // servers stay silent. Both are fine, but a server that answers INFO with
    // tls_required=false and no TLS on offer will never handshake.
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
                          endpoint the operator sent you in registration step 3."
                        .into(),
                }),
            });
        }
    }

    let server_name = ServerName::try_from(ep.host.clone())
        .map_err(|_| anyhow!("{:?} is not usable as a TLS server name", ep.host))?;
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
            return Ok(Handshake {
                server_cert: seen.clone(),
                outcome: Err(classify_handshake_error(&e, ep, seen.as_ref(), source_id)),
            })
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

    // Force any deferred client-certificate rejection into the open: under
    // TLS 1.3 the server only alerts after the handshake "succeeds".
    let _ = tls.write_all(b"PING\r\n").await;
    let mut buf = vec![0u8; 4096];
    let post = tokio::time::timeout(Duration::from_millis(2000), tls.read(&mut buf)).await;
    let outcome = match post {
        Ok(Ok(0)) => Err(Diagnosis {
            problem: "the server closed the connection right after the handshake".into(),
            fix: client_cert_fix(source_id),
        }),
        Ok(Ok(n)) => {
            let text = String::from_utf8_lossy(&buf[..n]).to_string();
            if text.contains("-ERR") {
                Err(Diagnosis {
                    problem: format!(
                        "TLS is fine, but NATS refused this connector: {}",
                        text.trim()
                    ),
                    fix: format!(
                        "The transport works and the refusal is authorization. Ask the operator \
                         to grant this identity publish permission on ajar.ingest.{source_id} \
                         (registration step 3 covers this)."
                    ),
                })
            } else {
                Ok(format!(
                    "TLS established and the server answered ({})",
                    text.lines().next().unwrap_or("").trim()
                ))
            }
        }
        Ok(Err(e)) => Err(classify_post_handshake_error(&e, source_id)),
        Err(_) => Ok(
            "TLS established; the server accepted the connection and stayed quiet \
             (some servers wait for CONNECT)"
                .to_string(),
        ),
    };

    Ok(Handshake {
        server_cert: seen,
        outcome,
    })
}

fn classify_handshake_error(
    e: &std::io::Error,
    ep: &Endpoint,
    seen: Option<&CertInfo>,
    source_id: &str,
) -> Diagnosis {
    let Some(rustls_err) = e.get_ref().and_then(|i| i.downcast_ref::<rustls::Error>()) else {
        return Diagnosis {
            problem: format!("the TLS handshake failed: {e}"),
            fix: "The error above is not a certificate problem. If the endpoint is not a NATS \
                  server on a TLS port, fix nats_url; otherwise send this exact message to the \
                  operator."
                .into(),
        };
    };
    classify_rustls_error(rustls_err, ep, seen, source_id)
}

/// Turn a rustls error into the onboarding step that actually failed.
pub fn classify_rustls_error(
    err: &rustls::Error,
    ep: &Endpoint,
    seen: Option<&CertInfo>,
    source_id: &str,
) -> Diagnosis {
    use rustls::Error as E;
    match err {
        E::InvalidCertificate(ce) => match ce {
            // UnknownIssuer: no trusted root matches. BadSignature: a root
            // matches by name but the signature does not check out (a re-keyed
            // CA with the same DN). To the partner both mean the same thing:
            // the CA file does not validate this server.
            CertificateError::UnknownIssuer | CertificateError::BadSignature => Diagnosis {
                problem: "the server's certificate is not signed by the CA in AJAR_TLS_CA".into(),
                fix: "You have the wrong CA file for this endpoint. Get the operator's current \
                      CA bundle (the one that signed the SERVER certificate) and point \
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

fn classify_post_handshake_error(e: &std::io::Error, source_id: &str) -> Diagnosis {
    if let Some(rustls::Error::AlertReceived(alert)) =
        e.get_ref().and_then(|i| i.downcast_ref::<rustls::Error>())
    {
        return Diagnosis {
            problem: format!(
                "the server accepted the handshake, then rejected this connector's client \
                 certificate ({alert:?})"
            ),
            fix: client_cert_fix(source_id),
        };
    }
    Diagnosis {
        problem: format!("the connection failed right after the handshake: {e}"),
        fix: client_cert_fix(source_id),
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
    fn a_wrong_ca_names_the_ca_file_not_the_handshake() {
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
    fn a_san_mismatch_lists_what_the_certificate_does_cover() {
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
    fn a_san_less_certificate_is_called_out_explicitly() {
        let d = classify_rustls_error(
            &rustls::Error::InvalidCertificate(CertificateError::NotValidForName),
            &ep(),
            Some(&cert(&[])),
            "acme-radar-1",
        );
        assert!(d.problem.contains("no subjectAltName"));
    }

    #[test]
    fn expiry_and_not_yet_valid_both_point_at_the_clock() {
        let d = classify_rustls_error(
            &rustls::Error::InvalidCertificate(CertificateError::Expired),
            &ep(),
            Some(&cert(&[])),
            "s",
        );
        assert!(d.fix.contains("date -u"));
        let d = classify_rustls_error(
            &rustls::Error::InvalidCertificate(CertificateError::NotValidYet),
            &ep(),
            Some(&cert(&[])),
            "s",
        );
        assert!(d.fix.contains("BEHIND"));
    }

    #[test]
    fn a_server_alert_blames_the_client_certificate_with_the_cn_rule() {
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
    fn the_policy_table_matches_the_runtime_exactly() {
        // Serialized against other env-reading tests by using unique names is
        // not possible here (the runtime's names are fixed), so this test owns
        // all three variables and restores the world after itself.
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

        // Whitespace counts as unset, exactly like the runtime.
        std::env::set_var("AJAR_TLS_KEY", "   ");
        assert!(matches!(policy(false), Policy::Partial { .. }));

        for (n, v) in saved {
            match v {
                Some(v) => std::env::set_var(n, v),
                None => std::env::remove_var(n),
            }
        }
    }
}
