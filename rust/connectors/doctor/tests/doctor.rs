// SPDX-License-Identifier: Apache-2.0
//! The doctor's failure matrix, against real listeners on loopback: every
//! way a partner's first hour actually goes wrong is fabricated here (throwaway
//! rcgen PKI, no fixtures, no network beyond loopback), and the test asserts
//! the doctor names the right onboarding step in plain words.
//!
//! This suite is the gate the doctor ships behind: a diagnosis that stops
//! matching its failure mode fails here, not in a partner's terminal.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ajar_doctor::{net, report, tls, Options};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::rustls::pki_types::PrivateKeyDer;
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{RootCertStore, ServerConfig};
use tokio_rustls::TlsAcceptor;

const WAIT: Duration = Duration::from_secs(5);

/// `run()` reads the process-global AJAR_TLS_* environment, so the tests that
/// own it are serialized behind this lock (async, so holding it across the
/// awaited runs is the intended use).
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The throwaway CA type rcgen 0.14 mints.
type Ca = rcgen::CertifiedIssuer<'static, rcgen::KeyPair>;

fn install_ring() {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
}

/// A CA and the PEM of its certificate.
fn mint_ca() -> (Ca, String) {
    // Each CA gets a distinct DN; identically named CAs exist in the wild but
    // make webpki report BadSignature instead of UnknownIssuer, and the wrong-CA
    // test wants to walk the UnknownIssuer route (the classifier folds both).
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, format!("doctor test ca {n}"));
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = rcgen::CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();
    let pem = ca.pem();
    (ca, pem)
}

/// A server certificate for `names`, optionally with a shifted validity window.
fn mint_server(
    ca: &Ca,
    names: &[&str],
    window_days: Option<(i64, i64)>,
) -> (rcgen::Certificate, rcgen::KeyPair) {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params =
        rcgen::CertificateParams::new(names.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .unwrap();
    if let Some((from, to)) = window_days {
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now + time::Duration::days(from);
        params.not_after = now + time::Duration::days(to);
    }
    let cert = params.signed_by(&key, ca).unwrap();
    (cert, key)
}

fn server_config(
    cert: &rcgen::Certificate,
    key: &rcgen::KeyPair,
    client_ca: Option<&Ca>,
) -> Arc<ServerConfig> {
    let builder = ServerConfig::builder();
    let builder = match client_ca {
        Some(ca) => {
            let mut roots = RootCertStore::empty();
            roots.add(ca.der().clone()).unwrap();
            builder.with_client_cert_verifier(
                WebPkiClientVerifier::builder(Arc::new(roots))
                    .build()
                    .unwrap(),
            )
        }
        None => builder.with_no_client_auth(),
    };
    Arc::new(
        builder
            .with_single_cert(
                vec![cert.der().clone()],
                PrivateKeyDer::try_from(key.serialize_der()).unwrap(),
            )
            .unwrap(),
    )
}

/// A one-connection TLS server that answers the first read with `reply`.
async fn spawn_tls_server(config: Arc<ServerConfig>, reply: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let acceptor = TlsAcceptor::from(config);
        // A failed handshake is the client's assertion, not ours.
        if let Ok(mut stream) = acceptor.accept(tcp).await {
            let mut buf = [0u8; 256];
            let _ = stream.read(&mut buf).await;
            let _ = stream.write_all(reply.as_bytes()).await;
            let _ = stream.flush().await;
            // Hold the connection open long enough for the client to read.
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    });
    addr
}

fn tmp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("ajar-doctor-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write(dir: &std::path::Path, name: &str, contents: &str) -> String {
    let p = dir.join(name);
    std::fs::write(&p, contents).unwrap();
    p.to_str().unwrap().to_string()
}

fn ep(host: &str, port: u16) -> net::Endpoint {
    net::Endpoint {
        host: host.into(),
        port,
        tls_scheme: true,
    }
}

#[tokio::test]
async fn the_happy_path_reports_tls_established() {
    install_ring();
    let (ca, ca_pem) = mint_ca();
    let (cert, key) = mint_server(&ca, &["localhost"], None);
    let addr = spawn_tls_server(server_config(&cert, &key, None), "PONG\r\n").await;
    let dir = tmp_dir("happy");
    let ca_path = write(&dir, "ca.pem", &ca_pem);

    let hs = tls::probe(
        &ep("localhost", addr.port()),
        &ca_path,
        None,
        "acme-radar-1",
        WAIT,
    )
    .await
    .unwrap();
    let detail = hs.outcome.expect("handshake should succeed");
    assert!(detail.contains("TLS established"), "{detail}");
    // The server certificate was captured for the clock check.
    let seen = hs.server_cert.expect("server cert recorded");
    assert!(seen.san.contains(&"localhost".to_string()));
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_wrong_ca_is_named_as_the_wrong_ca() {
    install_ring();
    let (ca_a, ca_a_pem) = mint_ca();
    let (ca_b, _) = mint_ca();
    let (cert, key) = mint_server(&ca_b, &["localhost"], None);
    let addr = spawn_tls_server(server_config(&cert, &key, None), "PONG\r\n").await;
    let dir = tmp_dir("wrongca");
    let ca_path = write(&dir, "ca.pem", &ca_a_pem);
    let _ = &ca_a;

    let hs = tls::probe(&ep("localhost", addr.port()), &ca_path, None, "s", WAIT)
        .await
        .unwrap();
    let d = hs.outcome.expect_err("must fail");
    assert!(
        d.problem.contains("not signed by the CA in AJAR_TLS_CA"),
        "{}",
        d.problem
    );
    assert!(d.fix.contains("CA bundle"), "{}", d.fix);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_san_mismatch_lists_the_names_the_certificate_covers() {
    install_ring();
    let (ca, ca_pem) = mint_ca();
    let (cert, key) = mint_server(&ca, &["somewhere.else"], None);
    let addr = spawn_tls_server(server_config(&cert, &key, None), "PONG\r\n").await;
    let dir = tmp_dir("san");
    let ca_path = write(&dir, "ca.pem", &ca_pem);

    let hs = tls::probe(&ep("localhost", addr.port()), &ca_path, None, "s", WAIT)
        .await
        .unwrap();
    let d = hs.outcome.expect_err("must fail");
    assert!(
        d.problem.contains("does not cover \"localhost\""),
        "{}",
        d.problem
    );
    assert!(d.problem.contains("somewhere.else"), "{}", d.problem);
    assert!(d.fix.contains("subjectAltName"), "{}", d.fix);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn an_expired_server_certificate_points_at_renewal_and_the_clock() {
    install_ring();
    let (ca, ca_pem) = mint_ca();
    let (cert, key) = mint_server(&ca, &["localhost"], Some((-30, -1)));
    let addr = spawn_tls_server(server_config(&cert, &key, None), "PONG\r\n").await;
    let dir = tmp_dir("expired");
    let ca_path = write(&dir, "ca.pem", &ca_pem);

    let hs = tls::probe(&ep("localhost", addr.port()), &ca_path, None, "s", WAIT)
        .await
        .unwrap();
    let d = hs.outcome.expect_err("must fail");
    assert!(d.problem.contains("expired"), "{}", d.problem);
    assert!(d.fix.contains("date -u"), "{}", d.fix);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_postdated_server_certificate_points_at_a_slow_clock() {
    install_ring();
    let (ca, ca_pem) = mint_ca();
    let (cert, key) = mint_server(&ca, &["localhost"], Some((1, 30)));
    let addr = spawn_tls_server(server_config(&cert, &key, None), "PONG\r\n").await;
    let dir = tmp_dir("postdated");
    let ca_path = write(&dir, "ca.pem", &ca_pem);

    let hs = tls::probe(&ep("localhost", addr.port()), &ca_path, None, "s", WAIT)
        .await
        .unwrap();
    let d = hs.outcome.expect_err("must fail");
    assert!(d.problem.contains("not valid yet"), "{}", d.problem);
    assert!(d.fix.contains("BEHIND"), "{}", d.fix);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_server_requiring_client_certificates_blames_the_client_certificate() {
    install_ring();
    let (ca, ca_pem) = mint_ca();
    let (cert, key) = mint_server(&ca, &["localhost"], None);
    // The server demands a client certificate; the probe presents none.
    let addr = spawn_tls_server(server_config(&cert, &key, Some(&ca)), "PONG\r\n").await;
    let dir = tmp_dir("clientcert");
    let ca_path = write(&dir, "ca.pem", &ca_pem);

    let hs = tls::probe(
        &ep("localhost", addr.port()),
        &ca_path,
        None,
        "acme-radar-1",
        WAIT,
    )
    .await
    .unwrap();
    let d = hs.outcome.expect_err("must fail");
    // Whether the alert lands during the handshake or on the first read, the
    // fix must walk the partner through their client certificate.
    assert!(d.fix.contains("acme-radar-1"), "{}", d.fix);
    assert!(d.fix.contains("CN"), "{}", d.fix);
}

#[tokio::test]
async fn a_dead_port_and_a_bad_name_are_told_apart() {
    // A port with nothing behind it: bind, take the port, drop the listener.
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    match net::dial(&ep("127.0.0.1", port), Duration::from_secs(2)).await {
        net::Dial::NoAnswer(e) => assert!(!e.is_empty()),
        other => panic!("expected NoAnswer, got {other:?}"),
    }
    // A name that cannot resolve anywhere, per RFC 6761.
    match net::dial(&ep("doctor-test.invalid", 4222), Duration::from_secs(2)).await {
        net::Dial::NoDns(_) => {}
        other => panic!("expected NoDns, got {other:?}"),
    }
}

#[tokio::test]
async fn a_cleartext_server_is_flagged_when_mtls_is_expected() {
    install_ring();
    let (_, ca_pem) = mint_ca();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut tcp, _) = listener.accept().await.unwrap();
        let _ = tcp
            .write_all(b"INFO {\"server_id\":\"T\",\"tls_required\":false}\r\n")
            .await;
        tokio::time::sleep(Duration::from_millis(500)).await;
    });
    let dir = tmp_dir("cleartext");
    let ca_path = write(&dir, "ca.pem", &ca_pem);

    let hs = tls::probe(&ep("127.0.0.1", addr.port()), &ca_path, None, "s", WAIT)
        .await
        .unwrap();
    let d = hs.outcome.expect_err("must fail");
    assert!(d.problem.contains("WITHOUT TLS"), "{}", d.problem);
    assert!(d.fix.contains("nats_url"), "{}", d.fix);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn an_authorization_refusal_is_separated_from_transport_failures() {
    install_ring();
    let (ca, ca_pem) = mint_ca();
    let (cert, key) = mint_server(&ca, &["localhost"], None);
    let addr = spawn_tls_server(
        server_config(&cert, &key, None),
        "-ERR 'Authorization Violation'\r\n",
    )
    .await;
    let dir = tmp_dir("authz");
    let ca_path = write(&dir, "ca.pem", &ca_pem);

    let hs = tls::probe(
        &ep("localhost", addr.port()),
        &ca_path,
        None,
        "acme-radar-1",
        WAIT,
    )
    .await
    .unwrap();
    let d = hs.outcome.expect_err("must fail");
    assert!(d.problem.contains("TLS is fine"), "{}", d.problem);
    assert!(d.fix.contains("ajar.ingest.acme-radar-1"), "{}", d.fix);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The full `run()` walk, covering the checks the TLS matrix above does not:
/// config faults, key faults, registration against a sink's sources_dir, and
/// the cleartext dev warning. One test function because `run()` reads the
/// AJAR_TLS_* environment, which is process-global.
#[tokio::test]
async fn the_full_run_names_the_broken_onboarding_step() {
    let _env = ENV_LOCK.lock().await;
    for name in [
        "AJAR_TLS_CA",
        "AJAR_TLS_CERT",
        "AJAR_TLS_KEY",
        "AJAR_REQUIRE_TLS",
    ] {
        std::env::remove_var(name);
    }
    let dir = tmp_dir("run");

    // A config that does not parse blocks everything, and says so.
    let broken = write(&dir, "broken.toml", "source_id = \"x\"\n# nothing else");
    let findings = ajar_doctor::run(&Options {
        config_path: Some(broken),
        sources_dir: None,
        timeout: Duration::from_secs(2),
    })
    .await;
    let (text, healthy) = report::render(&findings);
    assert!(!healthy);
    assert!(text.contains("Start with the first one: config."), "{text}");
    assert!(text.contains("blocked until the config loads"), "{text}");

    // A cleartext NATS answering on loopback, so the endpoint step passes.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut tcp, _)) = listener.accept().await else {
                break;
            };
            let _ = tcp
                .write_all(b"INFO {\"server_id\":\"T\",\"tls_required\":false}\r\n")
                .await;
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    });

    // A good seed whose source is not in the sink's registry: the fix says
    // how to register, and lists what IS registered.
    let seed = [0x42u8; 32];
    let seed_path = dir.join("acme-radar-1.seed");
    std::fs::write(&seed_path, seed).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&seed_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let sources = dir.join("sources");
    std::fs::create_dir_all(&sources).unwrap();
    std::fs::write(sources.join("other-source.pub"), "ab".repeat(32)).unwrap();

    let config = write(
        &dir,
        "connector.toml",
        &format!(
            "source_id = \"acme-radar-1\"\n\
             nats_url = \"nats://127.0.0.1:{port}\"\n\
             signing_key_path = \"{}\"\n\
             [transport]\n\
             kind = \"udp\"\n\
             bind = \"127.0.0.1:0\"\n",
            seed_path.display()
        ),
    );
    let findings = ajar_doctor::run(&Options {
        config_path: Some(config.clone()),
        sources_dir: Some(sources.to_str().unwrap().to_string()),
        timeout: Duration::from_secs(2),
    })
    .await;
    let (text, healthy) = report::render(&findings);
    assert!(!healthy);
    assert!(text.contains("no acme-radar-1.pub"), "{text}");
    assert!(text.contains("other-source"), "{text}");
    assert!(text.contains("ajar-sink mint acme-radar-1"), "{text}");
    // The endpoint and key steps still ran and passed.
    assert!(text.contains("speaks NATS"), "{text}");
    assert!(text.contains("derives public key"), "{text}");
    // Cleartext against a server that does not demand TLS: a warning, not a failure.
    assert!(text.contains("dev only"), "{text}");

    // Register it properly: the registration step turns green.
    let derived = {
        use ed25519_dalek::SigningKey;
        hex::encode(SigningKey::from_bytes(&seed).verifying_key().to_bytes())
    };
    std::fs::write(sources.join("acme-radar-1.pub"), &derived).unwrap();
    let findings = ajar_doctor::run(&Options {
        config_path: Some(config.clone()),
        sources_dir: Some(sources.to_str().unwrap().to_string()),
        timeout: Duration::from_secs(2),
    })
    .await;
    let (text, healthy) = report::render(&findings);
    assert!(healthy, "{text}");
    assert!(text.contains("matches the loaded seed"), "{text}");
    // No spool configured: the doctor teaches the one-liner instead.
    assert!(text.contains("store-and-forward"), "{text}");

    // With the one-line spool, the doctor proves the directory is usable.
    let spool_config = write(
        &dir,
        "spooled.toml",
        &format!(
            "spool = \"{}\"\n\
             source_id = \"acme-radar-1\"\n\
             nats_url = \"nats://127.0.0.1:{port}\"\n\
             signing_key_path = \"{}\"\n\
             [transport]\n\
             kind = \"udp\"\n\
             bind = \"127.0.0.1:0\"\n",
            dir.join("spool").display(),
            seed_path.display()
        ),
    );
    let findings = ajar_doctor::run(&Options {
        config_path: Some(spool_config),
        sources_dir: Some(sources.to_str().unwrap().to_string()),
        timeout: Duration::from_secs(2),
    })
    .await;
    let (text, healthy) = report::render(&findings);
    assert!(healthy, "{text}");
    assert!(text.contains("is writable, nothing queued"), "{text}");

    // A stale sibling .pub next to the seed: the classic rotated-one-half slip.
    std::fs::write(dir.join("acme-radar-1.pub"), "cd".repeat(32)).unwrap();
    let findings = ajar_doctor::run(&Options {
        config_path: Some(config),
        sources_dir: None,
        timeout: Duration::from_secs(2),
    })
    .await;
    let (text, healthy) = report::render(&findings);
    assert!(!healthy);
    assert!(text.contains("no longer match"), "{text}");

    // The phases above leave a stale sibling .pub; these phases test other
    // steps, so restore the key to healthy first.
    let _ = std::fs::remove_file(dir.join("acme-radar-1.pub"));

    // The transport preflight: a serial device that is not there is the
    // first naval failure mode, named with the plug-it-in fix.
    let serial_config = write(
        &dir,
        "serial.toml",
        &format!(
            "source_id = \"acme-radar-1\"\n\
             nats_url = \"nats://127.0.0.1:{port}\"\n\
             signing_key_path = \"{}\"\n\
             [transport]\n\
             kind = \"serial\"\n\
             device = \"{}\"\n",
            seed_path.display(),
            dir.join("no-such-tty").display()
        ),
    );
    let (text, healthy) = report::render(
        &ajar_doctor::run(&Options {
            config_path: Some(serial_config),
            sources_dir: None,
            timeout: Duration::from_secs(2),
        })
        .await,
    );
    assert!(!healthy);
    assert!(text.contains("does not exist"), "{text}");
    assert!(text.contains("plugged in"), "{text}");

    // Present-and-readable is the healthy half of the same check.
    let fake_tty = write(&dir, "ttyFAKE", "");
    let serial_ok = write(
        &dir,
        "serial-ok.toml",
        &format!(
            "source_id = \"acme-radar-1\"\n\
             nats_url = \"nats://127.0.0.1:{port}\"\n\
             signing_key_path = \"{}\"\n\
             [transport]\n\
             kind = \"serial\"\n\
             device = \"{fake_tty}\"\n\
             baud = 38400\n",
            seed_path.display()
        ),
    );
    let (text, _) = report::render(
        &ajar_doctor::run(&Options {
            config_path: Some(serial_ok),
            sources_dir: None,
            timeout: Duration::from_secs(2),
        })
        .await,
    );
    assert!(text.contains("present and readable"), "{text}");

    // A failover list with a dead standby: the doctor probes EVERY endpoint
    // and names the one that will let the drill down.
    let dead_port2 = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let failover_config = write(
        &dir,
        "failover.toml",
        &format!(
            "source_id = \"acme-radar-1\"\n\
             nats_url = \"nats://127.0.0.1:{port},nats://127.0.0.1:{dead_port2}\"\n\
             signing_key_path = \"{}\"\n\
             [transport]\n\
             kind = \"udp\"\n\
             bind = \"127.0.0.1:0\"\n",
            seed_path.display()
        ),
    );
    let (text, healthy) = report::render(
        &ajar_doctor::run(&Options {
            config_path: Some(failover_config),
            sources_dir: None,
            timeout: Duration::from_secs(2),
        })
        .await,
    );
    assert!(
        healthy,
        "a dead standby is a warning, not a failure: {text}"
    );
    assert!(text.contains("standby endpoint(s) not answering"), "{text}");
    assert!(text.contains(&dead_port2.to_string()), "{text}");

    // A seed that is neither 32 bytes nor hex: the fix names the mint command.
    let bad_seed = write(&dir, "bad.seed", "definitely not a key");
    let config2 = write(
        &dir,
        "connector2.toml",
        &format!(
            "source_id = \"acme-radar-1\"\n\
             nats_url = \"nats://127.0.0.1:{port}\"\n\
             signing_key_path = \"{bad_seed}\"\n\
             [transport]\n\
             kind = \"udp\"\n\
             bind = \"127.0.0.1:0\"\n"
        ),
    );
    let findings = ajar_doctor::run(&Options {
        config_path: Some(config2),
        sources_dir: None,
        timeout: Duration::from_secs(2),
    })
    .await;
    let (text, healthy) = report::render(&findings);
    assert!(!healthy);
    assert!(text.contains("ajar-sink mint"), "{text}");

    // With no config file at all, the doctor reads the environment the
    // embedding guides use; missing variables are named, present ones work.
    for name in ["NATS_URL", "AJAR_SOURCE_ID", "AJAR_SIGNING_SEED"] {
        std::env::remove_var(name);
    }
    let findings = ajar_doctor::run(&Options {
        config_path: None,
        sources_dir: None,
        timeout: Duration::from_secs(2),
    })
    .await;
    let (text, healthy) = report::render(&findings);
    assert!(!healthy);
    assert!(
        text.contains("NATS_URL, AJAR_SOURCE_ID, AJAR_SIGNING_SEED"),
        "{text}"
    );

    // The stale sibling .pub from the phase above would (rightly) fail the
    // key check; this phase is about the environment path, so clear it.
    let _ = std::fs::remove_file(dir.join("acme-radar-1.pub"));
    std::env::set_var("NATS_URL", format!("nats://127.0.0.1:{port}"));
    std::env::set_var("AJAR_SOURCE_ID", "acme-radar-1");
    std::env::set_var("AJAR_SIGNING_SEED", &seed_path);
    let findings = ajar_doctor::run(&Options {
        config_path: None,
        sources_dir: None,
        timeout: Duration::from_secs(2),
    })
    .await;
    let (text, healthy) = report::render(&findings);
    assert!(healthy, "{text}");
    assert!(text.contains("speaks NATS"), "{text}");
    for name in ["NATS_URL", "AJAR_SOURCE_ID", "AJAR_SIGNING_SEED"] {
        std::env::remove_var(name);
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// The mTLS half of the full `run()` walk: policy verdicts, certificate file
/// checks, the live handshake and the clock, plus the partial and
/// required-but-missing policy failures.
#[tokio::test]
async fn the_full_run_walks_the_mtls_path_end_to_end() {
    let _env = ENV_LOCK.lock().await;
    install_ring();
    let dir = tmp_dir("run-mtls");

    // A PKI whose client certificate carries CN = source_id, per the docs.
    let (ca, ca_pem) = mint_ca();
    let (server_cert, server_key) = mint_server(&ca, &["localhost"], None);
    let client_key = rcgen::KeyPair::generate().unwrap();
    let mut client_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
    client_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "acme-radar-1");
    let client_cert = client_params.signed_by(&client_key, &ca).unwrap();

    let ca_path = write(&dir, "ca.pem", &ca_pem);
    let cert_path = write(&dir, "client.pem", &client_cert.pem());
    let key_path = write(&dir, "client.key", &client_key.serialize_pem());

    // A many-connection TLS server: run() dials once for the endpoint check
    // and once more for the probe.
    let config = server_config(&server_cert, &server_key, Some(&ca));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let acceptor = TlsAcceptor::from(config.clone());
            tokio::spawn(async move {
                if let Ok(mut stream) = acceptor.accept(tcp).await {
                    let mut buf = [0u8; 256];
                    let _ = stream.read(&mut buf).await;
                    let _ = stream.write_all(b"PONG\r\n").await;
                    let _ = stream.flush().await;
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            });
        }
    });

    let seed = [0x42u8; 32];
    let seed_path = dir.join("acme-radar-1.seed");
    std::fs::write(&seed_path, seed).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&seed_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let config_path = write(
        &dir,
        "connector.toml",
        &format!(
            "source_id = \"acme-radar-1\"\n\
             nats_url = \"tls://localhost:{port}\"\n\
             signing_key_path = \"{}\"\n\
             [transport]\n\
             kind = \"udp\"\n\
             bind = \"127.0.0.1:0\"\n",
            seed_path.display()
        ),
    );
    let opts = |config_path: &str| Options {
        config_path: Some(config_path.to_string()),
        sources_dir: None,
        timeout: Duration::from_secs(3),
    };

    // A tls:// URL with no AJAR_TLS_* at all: the policy step fails the way
    // the runtime would, and the TLS steps are skipped, not guessed.
    for name in [
        "AJAR_TLS_CA",
        "AJAR_TLS_CERT",
        "AJAR_TLS_KEY",
        "AJAR_REQUIRE_TLS",
    ] {
        std::env::remove_var(name);
    }
    let (text, healthy) = report::render(&ajar_doctor::run(&opts(&config_path)).await);
    assert!(!healthy);
    assert!(text.contains("TLS is required"), "{text}");
    assert!(text.contains("no mTLS configured"), "{text}");

    // A partial triple: named as the slip it is.
    std::env::set_var("AJAR_TLS_CA", &ca_path);
    let (text, healthy) = report::render(&ajar_doctor::run(&opts(&config_path)).await);
    assert!(!healthy);
    assert!(text.contains("partial TLS configuration"), "{text}");
    assert!(text.contains("AJAR_TLS_CERT"), "{text}");

    // The full triple against a live mutual-TLS server: healthy end to end.
    std::env::set_var("AJAR_TLS_CERT", &cert_path);
    std::env::set_var("AJAR_TLS_KEY", &key_path);
    let (text, healthy) = report::render(&ajar_doctor::run(&opts(&config_path)).await);
    assert!(healthy, "{text}");
    assert!(text.contains("mTLS"), "{text}");
    assert!(text.contains("matches source_id"), "{text}");
    assert!(text.contains("TLS established"), "{text}");
    assert!(
        text.contains("inside the server certificate's validity"),
        "{text}"
    );

    // Cert and key swapped: the certificate-files step names the slip and the
    // handshake is not attempted against the server.
    std::env::set_var("AJAR_TLS_CERT", &key_path);
    std::env::set_var("AJAR_TLS_KEY", &cert_path);
    let (text, healthy) = report::render(&ajar_doctor::run(&opts(&config_path)).await);
    assert!(!healthy);
    assert!(text.contains("swapped"), "{text}");

    // A client certificate whose CN is not the source_id: flagged, not fatal.
    let other_key = rcgen::KeyPair::generate().unwrap();
    let mut other_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
    other_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "someone-else");
    let other_cert = other_params.signed_by(&other_key, &ca).unwrap();
    let other_cert_path = write(&dir, "other.pem", &other_cert.pem());
    let other_key_path = write(&dir, "other.key", &other_key.serialize_pem());
    std::env::set_var("AJAR_TLS_CERT", &other_cert_path);
    std::env::set_var("AJAR_TLS_KEY", &other_key_path);
    let (text, _) = report::render(&ajar_doctor::run(&opts(&config_path)).await);
    assert!(text.contains("CN is \"someone-else\""), "{text}");

    // mTLS configured but the endpoint is dead: the TLS steps say what they
    // are waiting on instead of piling on.
    let dead_port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    std::env::set_var("AJAR_TLS_CERT", &cert_path);
    std::env::set_var("AJAR_TLS_KEY", &key_path);
    let dead_config = write(
        &dir,
        "dead.toml",
        &format!(
            "source_id = \"acme-radar-1\"\n\
             nats_url = \"tls://127.0.0.1:{dead_port}\"\n\
             signing_key_path = \"{}\"\n\
             [transport]\n\
             kind = \"udp\"\n\
             bind = \"127.0.0.1:0\"\n",
            seed_path.display()
        ),
    );
    let (text, healthy) = report::render(&ajar_doctor::run(&opts(&dead_config)).await);
    assert!(!healthy);
    assert!(text.contains("did not answer"), "{text}");
    assert!(
        text.contains("blocked until the endpoint answers"),
        "{text}"
    );

    // A dead tls:// endpoint with no AJAR_TLS_* still forbids cleartext: the
    // TLS demand comes from the URL, not from whether the endpoint answered.
    for name in ["AJAR_TLS_CA", "AJAR_TLS_CERT", "AJAR_TLS_KEY"] {
        std::env::remove_var(name);
    }
    let (text, healthy) = report::render(&ajar_doctor::run(&opts(&dead_config)).await);
    assert!(!healthy);
    assert!(text.contains("TLS is required"), "{text}");
    let _ = std::fs::remove_dir_all(&dir);
}
