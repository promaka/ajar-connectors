// SPDX-License-Identifier: Apache-2.0
//! TAK link acceptance tests against an in-test mutual-TLS CoT sink.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use ajar_tak_egress::{Relay, TakConfig, TakLink};
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_rustls::rustls::pki_types::PrivateKeyDer;
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{RootCertStore, ServerConfig};
use tokio_rustls::TlsAcceptor;

use tempfile::TempDir;

/// The relay's CA and client PEMs in a temp dir, and the sink's acceptor.
struct Pki {
    dir: TempDir,
    acceptor: TlsAcceptor,
}

fn mint_pki() -> Pki {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = rcgen::CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();

    let server_key = rcgen::KeyPair::generate().unwrap();
    let server_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let server_cert = server_params.signed_by(&server_key, &ca).unwrap();

    let client_key = rcgen::KeyPair::generate().unwrap();
    let client_params = rcgen::CertificateParams::new(vec!["egress-relay".to_string()]).unwrap();
    let client_cert = client_params.signed_by(&client_key, &ca).unwrap();

    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("ca.crt"), ca.pem()).unwrap();
    std::fs::write(dir.path().join("client.crt"), client_cert.pem()).unwrap();
    std::fs::write(dir.path().join("client.key"), client_key.serialize_pem()).unwrap();

    let mut roots = RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .unwrap();
    let server_config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![server_cert.der().clone()],
            PrivateKeyDer::try_from(server_key.serialize_der()).unwrap(),
        )
        .unwrap();

    Pki {
        dir,
        acceptor: TlsAcceptor::from(Arc::new(server_config)),
    }
}

/// A mutual-TLS sink streaming every chunk it reads to `rx`. `stop` frees the
/// port so a new sink can bind the same address.
struct Sink {
    addr: String,
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    task: JoinHandle<()>,
}

impl Sink {
    fn stop(self) -> String {
        self.task.abort();
        self.addr
    }
}

async fn bind_sink(pki: &Pki, addr: &str) -> Sink {
    let listener = TcpListener::bind(addr).await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let (tx, rx) = mpsc::unbounded_channel();
    let acceptor = pki.acceptor.clone();
    let task = tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let Ok(mut tls) = acceptor.accept(tcp).await else {
                continue;
            };
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut chunk = [0u8; 4096];
                loop {
                    match tls.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if tx.send(chunk[..n].to_vec()).is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    Sink { addr, rx, task }
}

fn link_config(pki: &Pki) -> TakConfig {
    toml::from_str(&format!(
        r#"
        tls_ca = "{dir}/ca.crt"
        tls_cert = "{dir}/client.crt"
        tls_key = "{dir}/client.key"
        server_name = "localhost"
        buffer_max = 8
        "#,
        dir = pki.dir.path().display(),
    ))
    .unwrap()
}

const EVENT: &[u8] = br#"<event version="2.0" uid="AJ-GOV-1" type="a-f-A-M-F-Q" time="2026-06-10T08:00:00Z" start="2026-06-10T08:00:00Z" stale="2026-06-10T08:00:30Z"><point lat="26.4" lon="50.9" hae="1200.0" ce="10" le="10"/><detail><contact callsign="EAGLE01"/></detail></event>"#;

async fn recv_exactly(sink: &mut Sink, n: usize) -> Vec<u8> {
    let mut got = Vec::new();
    while got.len() < n {
        let chunk = sink.rx.recv().await.expect("sink alive");
        got.extend_from_slice(&chunk);
    }
    got
}

#[tokio::test]
async fn governed_cot_arrives_byte_identical() {
    let pki = mint_pki();
    let mut sink = bind_sink(&pki, "127.0.0.1:0").await;
    let mut link = TakLink::new(&format!("tls://{}", sink.addr), &link_config(&pki)).unwrap();

    link.send(EVENT).await.unwrap();

    assert_eq!(
        recv_exactly(&mut sink, EVENT.len()).await,
        EVENT,
        "payload must be forwarded verbatim"
    );
    assert_eq!(link.up.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn link_reconnects_after_outage() {
    let pki = mint_pki();
    let addr = bind_sink(&pki, "127.0.0.1:0").await.stop();

    let mut relay = Relay::new(8);
    let mut link = TakLink::new(&format!("tls://{addr}"), &link_config(&pki)).unwrap();

    relay.push(bytes::Bytes::from_static(EVENT));
    relay.drain(&mut link).await;
    assert!(
        !relay.is_empty(),
        "event must remain buffered while TAK is down"
    );
    assert_eq!(link.up.load(Ordering::Relaxed), 0);
    assert_eq!(link.reconnects.load(Ordering::Relaxed), 0);

    let mut sink = bind_sink(&pki, &addr).await;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    while !relay.is_empty() && tokio::time::Instant::now() < deadline {
        relay.drain(&mut link).await;
        if !relay.is_empty() {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }
    assert!(
        relay.is_empty(),
        "relay must deliver once the server returns"
    );
    assert_eq!(link.reconnects.load(Ordering::Relaxed), 1);
    assert_eq!(link.up.load(Ordering::Relaxed), 1);
    assert_eq!(relay.metrics.delivered.load(Ordering::Relaxed), 1);
    assert_eq!(recv_exactly(&mut sink, EVENT.len()).await, EVENT);
}

/// NATS egress subject to relay to TAK sink; runs only with AJAR_TEST_NATS_URL.
#[tokio::test]
async fn nats_to_tak_full_loop() {
    let Ok(nats_url) = std::env::var("AJAR_TEST_NATS_URL") else {
        eprintln!("skipping nats_to_tak_full_loop (set AJAR_TEST_NATS_URL to run)");
        return;
    };
    let pki = mint_pki();
    let mut sink = bind_sink(&pki, "127.0.0.1:0").await;
    let cfg = ajar_tak_egress::EgressConfig::parse(&format!(
        r#"
        nats_url = "{nats_url}"
        egress_subject = "ajar.egress.cot.test"
        egress_verifying_key = "unused"
        target = "tls://{addr}"
        [tak]
        tls_ca = "{dir}/ca.crt"
        tls_cert = "{dir}/client.crt"
        tls_key = "{dir}/client.key"
        server_name = "localhost"
        "#,
        addr = sink.addr,
        dir = pki.dir.path().display(),
    ))
    .unwrap();

    let relay = tokio::spawn(ajar_tak_egress::run(cfg));
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let client = async_nats::connect(&nats_url).await.unwrap();
    client
        .publish("ajar.egress.cot.test", bytes::Bytes::from_static(EVENT))
        .await
        .unwrap();
    client.flush().await.unwrap();

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut received = Vec::new();
    while received.len() < EVENT.len() {
        let chunk = tokio::time::timeout_at(deadline, sink.rx.recv())
            .await
            .expect("event must arrive before deadline")
            .expect("sink alive");
        received.extend_from_slice(&chunk);
    }
    assert_eq!(received, EVENT);
    relay.abort();
}
