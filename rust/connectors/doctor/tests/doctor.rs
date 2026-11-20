// SPDX-License-Identifier: Apache-2.0
//! The doctor's failure matrix against real loopback listeners and a throwaway rcgen PKI.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ajar_doctor::{net, report, tls, Options, Role};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::MutexGuard;
use tokio_rustls::rustls::pki_types::PrivateKeyDer;
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{RootCertStore, ServerConfig};
use tokio_rustls::TlsAcceptor;

const WAIT: Duration = Duration::from_secs(5);
const SOURCE_ID: &str = "acme-radar-1";
const SEED: [u8; 32] = [0x42; 32];
const UDP_TRANSPORT: &str = "[transport]\nkind = \"udp\"\nbind = \"127.0.0.1:0\"\n";
const CLEARTEXT_INFO: &[u8] = b"INFO {\"server_id\":\"T\",\"tls_required\":false}\r\n";

/// `run()` reads the process-global environment; every test that calls it
/// holds this lock.
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

type Ca = rcgen::CertifiedIssuer<'static, rcgen::KeyPair>;

/// Takes the env lock and clears every variable `run()` reads.
async fn clean_env() -> MutexGuard<'static, ()> {
    let guard = ENV_LOCK.lock().await;
    for name in [
        "AJAR_TLS_CA",
        "AJAR_TLS_CERT",
        "AJAR_TLS_KEY",
        "AJAR_REQUIRE_TLS",
        "NATS_URL",
        "AJAR_SOURCE_ID",
        "AJAR_SIGNING_SEED",
    ] {
        std::env::remove_var(name);
    }
    guard
}

fn install_provider() {
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// A CA and its PEM.
fn mint_ca() -> (Ca, String) {
    // A distinct DN per CA: identically named CAs make webpki report
    // BadSignature instead of UnknownIssuer.
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
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

/// A server certificate for `names`, optionally with a validity window in
/// days relative to now.
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

/// A client certificate with CN `cn`, as (cert PEM, key PEM).
fn mint_client(ca: &Ca, cn: &str) -> (String, String) {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::new()).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    let cert = params.signed_by(&key, ca).unwrap();
    (cert.pem(), key.serialize_pem())
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

/// A TLS server that answers each connection's first read with `reply`, after a
/// CONNECT, and refuses anything else first, as NATS does with authentication on. A `|`
/// in `reply` splits it into writes a moment apart.
async fn spawn_tls_server(config: Arc<ServerConfig>, reply: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = TlsAcceptor::from(config.clone());
            tokio::spawn(async move {
                // A failed handshake is the client's to assert on.
                if let Ok(mut stream) = acceptor.accept(tcp).await {
                    let mut buf = [0u8; 256];
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    let answer = match buf[..n].starts_with(b"CONNECT ") {
                        true => reply,
                        false => "-ERR 'Authorization Violation'\r\n",
                    };
                    for part in answer.split('|') {
                        let _ = stream.write_all(part.as_bytes()).await;
                        let _ = stream.flush().await;
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            });
        }
    });
    addr
}

/// A cleartext NATS stand-in that greets every connection with INFO.
async fn spawn_cleartext_nats() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            let _ = tcp.write_all(CLEARTEXT_INFO).await;
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    });
    port
}

/// A loopback port with nothing listening.
fn dead_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn write(dir: &TempDir, name: &str, contents: &str) -> String {
    let p = dir.path().join(name);
    std::fs::write(&p, contents).unwrap();
    p.to_str().unwrap().to_string()
}

/// `SEED` at mode 600, so the key check passes without a permissions warning.
fn seed_file(dir: &TempDir) -> PathBuf {
    let path = dir.path().join(format!("{SOURCE_ID}.seed"));
    std::fs::write(&path, SEED).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    path
}

fn connector_toml(nats_url: &str, seed: impl std::fmt::Display, transport: &str) -> String {
    format!(
        "source_id = \"{SOURCE_ID}\"\n\
         nats_url = \"{nats_url}\"\n\
         signing_key_path = \"{seed}\"\n\
         {transport}"
    )
}

/// A config file for a healthy connector against `nats_url`.
fn config(dir: &TempDir, nats_url: &str) -> String {
    let seed = seed_file(dir);
    write(
        dir,
        "connector.toml",
        &connector_toml(nats_url, seed.display(), UDP_TRANSPORT),
    )
}

async fn doctor(config_path: Option<String>, sources_dir: Option<&Path>) -> (String, bool) {
    let findings = ajar_doctor::run(&Options {
        role: Role::Producer,
        config_path,
        sources_dir: sources_dir.map(|d| d.to_str().unwrap().to_string()),
        tls_files: None,
        timeout: Duration::from_secs(3),
    })
    .await;
    report::render(&findings)
}

fn ep(host: &str, port: u16) -> net::Endpoint {
    net::Endpoint {
        host: host.into(),
        port,
        tls_scheme: true,
    }
}

/// A probe with no client certificate, trusting only `trusted_ca_pem`.
async fn probe(addr: SocketAddr, host: &str, trusted_ca_pem: &str) -> tls::Handshake {
    let dir = tempfile::tempdir().unwrap();
    let ca_path = write(&dir, "ca.pem", trusted_ca_pem);
    tls::probe(&ep(host, addr.port()), &ca_path, None, SOURCE_ID, WAIT)
        .await
        .unwrap()
}

/// A registry dir holding `other-source.pub`.
fn sources_dir(dir: &TempDir) -> PathBuf {
    let sources = dir.path().join("sources");
    std::fs::create_dir_all(&sources).unwrap();
    std::fs::write(sources.join("other-source.pub"), "ab".repeat(32)).unwrap();
    sources
}

fn derived_pub_hex() -> String {
    use ed25519_dalek::SigningKey;
    hex::encode(SigningKey::from_bytes(&SEED).verifying_key().to_bytes())
}

/// The client-side mTLS files for a CA, and points `AJAR_TLS_*` at them.
struct Mtls {
    dir: TempDir,
    ca: Ca,
    ca_path: String,
    cert_path: String,
    key_path: String,
}

impl Mtls {
    fn new() -> Self {
        install_provider();
        let dir = tempfile::tempdir().unwrap();
        let (ca, ca_pem) = mint_ca();
        let (cert_pem, key_pem) = mint_client(&ca, SOURCE_ID);
        Self {
            ca_path: write(&dir, "ca.pem", &ca_pem),
            cert_path: write(&dir, "client.pem", &cert_pem),
            key_path: write(&dir, "client.key", &key_pem),
            dir,
            ca,
        }
    }

    fn export(&self, cert: &str, key: &str) {
        std::env::set_var("AJAR_TLS_CA", &self.ca_path);
        std::env::set_var("AJAR_TLS_CERT", cert);
        std::env::set_var("AJAR_TLS_KEY", key);
    }

    /// A live mutual-TLS server for `localhost`, and a config pointing at it.
    async fn serve(&self) -> String {
        let (cert, key) = mint_server(&self.ca, &["localhost"], None);
        let addr = spawn_tls_server(server_config(&cert, &key, Some(&self.ca)), "PONG\r\n").await;
        config(&self.dir, &format!("tls://localhost:{}", addr.port()))
    }
}

#[tokio::test]
async fn probe_happy_path_reports_tls_established() {
    install_provider();
    let (ca, ca_pem) = mint_ca();
    let (cert, key) = mint_server(&ca, &["localhost"], None);
    let addr = spawn_tls_server(server_config(&cert, &key, None), "PONG\r\n").await;

    let hs = probe(addr, "localhost", &ca_pem).await;
    let detail = hs.outcome.expect("handshake should succeed");
    assert!(detail.contains("TLS established"), "{detail}");
    let seen = hs
        .server_cert
        .expect("server cert recorded for the clock check");
    assert!(seen.san.contains(&"localhost".to_string()));
}

#[tokio::test]
async fn probe_names_the_wrong_ca() {
    install_provider();
    let (_, ca_a_pem) = mint_ca();
    let (ca_b, _) = mint_ca();
    let (cert, key) = mint_server(&ca_b, &["localhost"], None);
    let addr = spawn_tls_server(server_config(&cert, &key, None), "PONG\r\n").await;

    let d = probe(addr, "localhost", &ca_a_pem)
        .await
        .outcome
        .expect_err("must fail");
    assert!(
        d.problem.contains("not signed by the CA in AJAR_TLS_CA"),
        "{}",
        d.problem
    );
    assert!(d.fix.contains("CA bundle"), "{}", d.fix);
}

#[tokio::test]
async fn probe_san_mismatch_lists_covered_names() {
    install_provider();
    let (ca, ca_pem) = mint_ca();
    let (cert, key) = mint_server(&ca, &["somewhere.else"], None);
    let addr = spawn_tls_server(server_config(&cert, &key, None), "PONG\r\n").await;

    let d = probe(addr, "localhost", &ca_pem)
        .await
        .outcome
        .expect_err("must fail");
    assert!(
        d.problem.contains("does not cover \"localhost\""),
        "{}",
        d.problem
    );
    assert!(d.problem.contains("somewhere.else"), "{}", d.problem);
    assert!(d.fix.contains("subjectAltName"), "{}", d.fix);
}

#[tokio::test]
async fn probe_expired_server_cert_points_at_clock() {
    install_provider();
    let (ca, ca_pem) = mint_ca();
    let (cert, key) = mint_server(&ca, &["localhost"], Some((-30, -1)));
    let addr = spawn_tls_server(server_config(&cert, &key, None), "PONG\r\n").await;

    let d = probe(addr, "localhost", &ca_pem)
        .await
        .outcome
        .expect_err("must fail");
    assert!(d.problem.contains("expired"), "{}", d.problem);
    assert!(d.fix.contains("date -u"), "{}", d.fix);
}

#[tokio::test]
async fn probe_postdated_server_cert_points_at_slow_clock() {
    install_provider();
    let (ca, ca_pem) = mint_ca();
    let (cert, key) = mint_server(&ca, &["localhost"], Some((1, 30)));
    let addr = spawn_tls_server(server_config(&cert, &key, None), "PONG\r\n").await;

    let d = probe(addr, "localhost", &ca_pem)
        .await
        .outcome
        .expect_err("must fail");
    assert!(d.problem.contains("not valid yet"), "{}", d.problem);
    assert!(d.fix.contains("BEHIND"), "{}", d.fix);
}

#[tokio::test]
async fn probe_missing_client_cert_blames_client_cert() {
    install_provider();
    let (ca, ca_pem) = mint_ca();
    let (cert, key) = mint_server(&ca, &["localhost"], None);
    let addr = spawn_tls_server(server_config(&cert, &key, Some(&ca)), "PONG\r\n").await;

    let d = probe(addr, "localhost", &ca_pem)
        .await
        .outcome
        .expect_err("must fail");
    assert!(d.fix.contains(SOURCE_ID), "{}", d.fix);
    assert!(d.fix.contains("CN"), "{}", d.fix);
}

#[tokio::test]
async fn dial_tells_dead_port_from_bad_name() {
    match net::dial(&ep("127.0.0.1", dead_port()), Duration::from_secs(2)).await {
        net::Dial::NoAnswer(e) => assert!(!e.is_empty()),
        other => panic!("expected NoAnswer, got {other:?}"),
    }
    // RFC 6761: .invalid never resolves.
    match net::dial(&ep("doctor-test.invalid", 4222), Duration::from_secs(2)).await {
        net::Dial::NoDns(_) => {}
        other => panic!("expected NoDns, got {other:?}"),
    }
}

#[tokio::test]
async fn probe_flags_cleartext_server_under_mtls() {
    install_provider();
    let (_, ca_pem) = mint_ca();
    let port = spawn_cleartext_nats().await;

    let d = probe(([127, 0, 0, 1], port).into(), "127.0.0.1", &ca_pem)
        .await
        .outcome
        .expect_err("must fail");
    assert!(d.problem.contains("WITHOUT TLS"), "{}", d.problem);
    assert!(d.fix.contains("nats_url"), "{}", d.fix);
}

#[tokio::test]
async fn probe_separates_authorization_refusal() {
    install_provider();
    let (ca, ca_pem) = mint_ca();
    let (cert, key) = mint_server(&ca, &["localhost"], None);
    let addr = spawn_tls_server(
        server_config(&cert, &key, None),
        "-ERR 'Authorization Violation'\r\n",
    )
    .await;

    let d = probe(addr, "localhost", &ca_pem)
        .await
        .outcome
        .expect_err("must fail");
    assert!(d.problem.contains("TLS is fine"), "{}", d.problem);
    assert!(d.fix.contains("acme-radar-1"), "{}", d.fix);
}

#[tokio::test]
async fn probe_waits_past_the_servers_own_ping_for_the_refusal() {
    install_provider();
    let (ca, ca_pem) = mint_ca();
    let (cert, key) = mint_server(&ca, &["localhost"], None);
    let addr = spawn_tls_server(
        server_config(&cert, &key, None),
        "PING\r\n|-ERR 'Authorization Violation'\r\n",
    )
    .await;

    let d = probe(addr, "localhost", &ca_pem)
        .await
        .outcome
        .expect_err("must fail");
    assert!(
        d.problem.contains("Authorization Violation"),
        "{}",
        d.problem
    );
}

#[tokio::test]
async fn broken_config_blocks_every_step() {
    let _env = clean_env().await;
    let dir = tempfile::tempdir().unwrap();
    let broken = write(&dir, "broken.toml", "source_id = \"x\"\n# nothing else");

    let (text, healthy) = doctor(Some(broken), None).await;
    assert!(!healthy);
    assert!(text.contains("Start with the first one: config."), "{text}");
    assert!(text.contains("blocked until the config loads"), "{text}");
}

#[tokio::test]
async fn unregistered_source_lists_registered_names() {
    let _env = clean_env().await;
    let dir = tempfile::tempdir().unwrap();
    let port = spawn_cleartext_nats().await;
    let config = config(&dir, &format!("nats://127.0.0.1:{port}"));
    let sources = sources_dir(&dir);

    let (text, healthy) = doctor(Some(config), Some(&sources)).await;
    assert!(!healthy);
    assert!(text.contains("no acme-radar-1.pub"), "{text}");
    assert!(text.contains("other-source"), "{text}");
    assert!(text.contains("ajar-sink mint acme-radar-1"), "{text}");
    assert!(
        text.contains("speaks NATS"),
        "endpoint still checked: {text}"
    );
    assert!(
        text.contains("derives public key"),
        "key still checked: {text}"
    );
    assert!(text.contains("dev only"), "cleartext is a warning: {text}");
}

#[tokio::test]
async fn registered_source_is_healthy() {
    let _env = clean_env().await;
    let dir = tempfile::tempdir().unwrap();
    let port = spawn_cleartext_nats().await;
    let config = config(&dir, &format!("nats://127.0.0.1:{port}"));
    let sources = sources_dir(&dir);
    std::fs::write(sources.join("acme-radar-1.pub"), derived_pub_hex()).unwrap();

    let (text, healthy) = doctor(Some(config), Some(&sources)).await;
    assert!(healthy, "{text}");
    assert!(text.contains("matches the loaded seed"), "{text}");
    assert!(text.contains("store-and-forward"), "spool hint: {text}");
}

#[tokio::test]
async fn writable_spool_is_healthy() {
    let _env = clean_env().await;
    let dir = tempfile::tempdir().unwrap();
    let port = spawn_cleartext_nats().await;
    let seed = seed_file(&dir);
    let spooled = write(
        &dir,
        "spooled.toml",
        &format!(
            "spool = \"{}\"\n{}",
            dir.path().join("spool").display(),
            connector_toml(
                &format!("nats://127.0.0.1:{port}"),
                seed.display(),
                UDP_TRANSPORT
            )
        ),
    );

    let (text, healthy) = doctor(Some(spooled), None).await;
    assert!(healthy, "{text}");
    assert!(text.contains("is writable, nothing queued"), "{text}");
}

#[tokio::test]
async fn stale_sibling_pub_fails_the_key() {
    let _env = clean_env().await;
    let dir = tempfile::tempdir().unwrap();
    let port = spawn_cleartext_nats().await;
    let config = config(&dir, &format!("nats://127.0.0.1:{port}"));
    std::fs::write(dir.path().join("acme-radar-1.pub"), "cd".repeat(32)).unwrap();

    let (text, healthy) = doctor(Some(config), None).await;
    assert!(!healthy);
    assert!(text.contains("no longer match"), "{text}");
}

#[tokio::test]
async fn missing_serial_device_says_plug_it_in() {
    let _env = clean_env().await;
    let dir = tempfile::tempdir().unwrap();
    let port = spawn_cleartext_nats().await;
    let seed = seed_file(&dir);
    let transport = format!(
        "[transport]\nkind = \"serial\"\ndevice = \"{}\"\n",
        dir.path().join("no-such-tty").display()
    );
    let serial = write(
        &dir,
        "serial.toml",
        &connector_toml(
            &format!("nats://127.0.0.1:{port}"),
            seed.display(),
            &transport,
        ),
    );

    let (text, healthy) = doctor(Some(serial), None).await;
    assert!(!healthy);
    assert!(text.contains("does not exist"), "{text}");
    assert!(text.contains("plugged in"), "{text}");
}

#[tokio::test]
async fn readable_serial_device_passes() {
    let _env = clean_env().await;
    let dir = tempfile::tempdir().unwrap();
    let port = spawn_cleartext_nats().await;
    let seed = seed_file(&dir);
    let fake_tty = write(&dir, "ttyFAKE", "");
    let transport =
        format!("[transport]\nkind = \"serial\"\ndevice = \"{fake_tty}\"\nbaud = 38400\n");
    let serial = write(
        &dir,
        "serial-ok.toml",
        &connector_toml(
            &format!("nats://127.0.0.1:{port}"),
            seed.display(),
            &transport,
        ),
    );

    let (text, _) = doctor(Some(serial), None).await;
    assert!(text.contains("present and readable"), "{text}");
}

#[tokio::test]
async fn dead_standby_is_a_warning() {
    let _env = clean_env().await;
    let dir = tempfile::tempdir().unwrap();
    let port = spawn_cleartext_nats().await;
    let standby = dead_port();
    let config = config(
        &dir,
        &format!("nats://127.0.0.1:{port},nats://127.0.0.1:{standby}"),
    );

    let (text, healthy) = doctor(Some(config), None).await;
    assert!(
        healthy,
        "a dead standby is a warning, not a failure: {text}"
    );
    assert!(text.contains("standby endpoint(s) not answering"), "{text}");
    assert!(text.contains(&standby.to_string()), "{text}");
}

#[tokio::test]
async fn garbage_seed_names_the_mint_command() {
    let _env = clean_env().await;
    let dir = tempfile::tempdir().unwrap();
    let port = spawn_cleartext_nats().await;
    let bad_seed = write(&dir, "bad.seed", "definitely not a key");
    let config = write(
        &dir,
        "connector.toml",
        &connector_toml(&format!("nats://127.0.0.1:{port}"), bad_seed, UDP_TRANSPORT),
    );

    let (text, healthy) = doctor(Some(config), None).await;
    assert!(!healthy);
    assert!(text.contains("ajar-sink mint"), "{text}");
}

#[tokio::test]
async fn incomplete_environment_names_missing_vars() {
    let _env = clean_env().await;

    let (text, healthy) = doctor(None, None).await;
    assert!(!healthy);
    assert!(
        text.contains("NATS_URL, AJAR_SOURCE_ID, AJAR_SIGNING_SEED"),
        "{text}"
    );
}

#[tokio::test]
async fn environment_alone_is_enough() {
    let _env = clean_env().await;
    let dir = tempfile::tempdir().unwrap();
    let port = spawn_cleartext_nats().await;
    std::env::set_var("NATS_URL", format!("nats://127.0.0.1:{port}"));
    std::env::set_var("AJAR_SOURCE_ID", SOURCE_ID);
    std::env::set_var("AJAR_SIGNING_SEED", seed_file(&dir));

    let (text, healthy) = doctor(None, None).await;
    assert!(healthy, "{text}");
    assert!(text.contains("speaks NATS"), "{text}");
}

#[tokio::test]
async fn tls_url_without_tls_env_fails_policy() {
    let _env = clean_env().await;
    let mtls = Mtls::new();
    let config = mtls.serve().await;

    let (text, healthy) = doctor(Some(config), None).await;
    assert!(!healthy);
    assert!(text.contains("TLS is required"), "{text}");
    assert!(
        text.contains("no mTLS configured"),
        "TLS steps skipped: {text}"
    );
}

#[tokio::test]
async fn partial_tls_env_is_named() {
    let _env = clean_env().await;
    let mtls = Mtls::new();
    let config = mtls.serve().await;
    std::env::set_var("AJAR_TLS_CA", &mtls.ca_path);

    let (text, healthy) = doctor(Some(config), None).await;
    assert!(!healthy);
    assert!(text.contains("partial TLS configuration"), "{text}");
    assert!(text.contains("AJAR_TLS_CERT"), "{text}");
}

#[tokio::test]
async fn full_mtls_run_is_healthy() {
    let _env = clean_env().await;
    let mtls = Mtls::new();
    let config = mtls.serve().await;
    mtls.export(&mtls.cert_path, &mtls.key_path);

    let (text, healthy) = doctor(Some(config), None).await;
    assert!(healthy, "{text}");
    assert!(text.contains("mTLS"), "{text}");
    assert!(text.contains("matches source_id"), "{text}");
    assert!(text.contains("TLS established"), "{text}");
    assert!(
        text.contains("inside the server certificate's validity"),
        "{text}"
    );
}

#[tokio::test]
async fn swapped_cert_and_key_are_named() {
    let _env = clean_env().await;
    let mtls = Mtls::new();
    let config = mtls.serve().await;
    mtls.export(&mtls.key_path, &mtls.cert_path);

    let (text, healthy) = doctor(Some(config), None).await;
    assert!(!healthy);
    assert!(text.contains("swapped"), "{text}");
}

#[tokio::test]
async fn client_cn_mismatch_is_flagged() {
    let _env = clean_env().await;
    let mtls = Mtls::new();
    let config = mtls.serve().await;
    let (cert_pem, key_pem) = mint_client(&mtls.ca, "someone-else");
    let cert = write(&mtls.dir, "other.pem", &cert_pem);
    let key = write(&mtls.dir, "other.key", &key_pem);
    mtls.export(&cert, &key);

    let (text, _) = doctor(Some(config), None).await;
    assert!(text.contains("CN is \"someone-else\""), "{text}");
}

#[tokio::test]
async fn dead_mtls_endpoint_blocks_tls_steps() {
    let _env = clean_env().await;
    let mtls = Mtls::new();
    let config = config(&mtls.dir, &format!("tls://127.0.0.1:{}", dead_port()));
    mtls.export(&mtls.cert_path, &mtls.key_path);

    let (text, healthy) = doctor(Some(config), None).await;
    assert!(!healthy);
    assert!(text.contains("did not answer"), "{text}");
    assert!(
        text.contains("blocked until the endpoint answers"),
        "{text}"
    );
}

#[tokio::test]
async fn dead_tls_url_still_requires_tls() {
    let _env = clean_env().await;
    let dir = tempfile::tempdir().unwrap();
    let config = config(&dir, &format!("tls://127.0.0.1:{}", dead_port()));

    let (text, healthy) = doctor(Some(config), None).await;
    assert!(!healthy);
    assert!(text.contains("TLS is required"), "{text}");
}

/// The findings for a consumer whose config delivers to `target`.
async fn consumer_findings(target: &str) -> Vec<report::Finding> {
    let dir = tempfile::tempdir().unwrap();
    let config_path = write(
        &dir,
        "consumer.toml",
        &format!(
            "nats_url = \"nats://127.0.0.1:1\"\n\
             egress_subject = \"ajar.egress.cot.*\"\n\
             egress_verifying_key = \"/instance/egress.pub\"\n\
             target = \"{target}\"\n"
        ),
    );
    ajar_doctor::run(&Options {
        role: Role::Consumer {
            connector_id: "ally-feed".into(),
        },
        config_path: Some(config_path),
        sources_dir: None,
        tls_files: None,
        timeout: Duration::from_secs(3),
    })
    .await
}

fn finding<'a>(findings: &'a [report::Finding], step: &str) -> &'a report::Finding {
    findings.iter().find(|f| f.step == step).unwrap()
}

#[tokio::test]
async fn consumer_target_that_answers_passes() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let findings = consumer_findings(&format!("tls://{addr}")).await;
    let target = finding(&findings, "target");
    assert_eq!(target.status, report::Status::Ok, "{}", target.detail);
    assert_eq!(
        finding(&findings, "signing key").status,
        report::Status::Skip
    );
}

#[tokio::test]
async fn consumer_target_nobody_answers_fails() {
    let addr = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let findings = consumer_findings(&format!("{addr}")).await;
    let target = finding(&findings, "target");
    assert_eq!(target.status, report::Status::Fail);
    assert!(
        target.detail.contains("nothing answers"),
        "{}",
        target.detail
    );
}

#[tokio::test]
async fn consumer_datagram_target_is_skipped() {
    let findings = consumer_findings("udp://239.2.3.1:6969").await;
    assert_eq!(finding(&findings, "target").status, report::Status::Skip);
}
