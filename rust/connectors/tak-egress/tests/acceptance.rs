// SPDX-License-Identifier: Apache-2.0
//! Acceptance tests for the TAK egress link, against a real mutual-TLS CoT sink
//! stood up in-test (throwaway CA + server + client certs minted with rcgen —
//! no external PKI, no fixtures, no network beyond loopback).
//!
//! What must hold:
//!  1. a governed CoT payload arrives at the sink **byte-identical** (the
//!     verbatim rule is the governed guarantee);
//!  2. with the TAK Server down the link fails cleanly (no crash), and when the
//!     server returns the link reconnects and delivers.
//!
//! (2) is driven by server-down → server-up on the same port — a deterministic
//! outage. "Detect a mid-stream drop by a failed write" is deliberately not
//! asserted: TCP silently buffers the first write into a just-closed socket, so
//! it is inherently racy, and the relay is bounded-and-lossy there by design.
//!
//! The full NATS-in-the-loop test is env-gated (`AJAR_TEST_NATS_URL`) so `cargo
//! test` stays green on machines without a broker.

use std::io::Write as _;
use std::path::PathBuf;
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

/// A throwaway PKI: writes the relay-side PEMs (CA, client cert/key) to a temp
/// dir and holds a ready mutual-TLS acceptor for the sink side.
struct Pki {
    dir: PathBuf,
    acceptor: TlsAcceptor,
}

fn mint_pki(tag: &str) -> Pki {
    // rcgen 0.14: signing is done by an Issuer, which carries params + key.
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

    let dir = std::env::temp_dir().join(format!("ajar-tak-egress-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let write = |name: &str, text: String| {
        let mut f = std::fs::File::create(dir.join(name)).unwrap();
        f.write_all(text.as_bytes()).unwrap();
    };
    write("ca.crt", ca.pem());
    write("client.crt", client_cert.pem());
    write("client.key", client_key.serialize_pem());

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

/// A listening mutual-TLS sink. Every chunk read from any accepted connection is
/// streamed to `rx`. Dropping (via `stop`) frees the port so the sink can be
/// restarted on the same address to simulate a server outage.
struct Sink {
    addr: String,
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    task: JoinHandle<()>,
}

impl Sink {
    fn stop(self) -> String {
        self.task.abort(); // drops the listener → frees the port
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

fn link_config(pki: &Pki, addr: &str) -> TakConfig {
    toml::from_str(&format!(
        r#"
        url = "tls://{addr}"
        tls_ca = "{dir}/ca.crt"
        tls_cert = "{dir}/client.crt"
        tls_key = "{dir}/client.key"
        server_name = "localhost"
        buffer_max = 8
        "#,
        addr = addr,
        dir = pki.dir.display(),
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
    let pki = mint_pki("verbatim");
    let mut sink = bind_sink(&pki, "127.0.0.1:0").await;
    let mut link = TakLink::new(&link_config(&pki, &sink.addr)).unwrap();

    link.send(EVENT).await.unwrap();

    assert_eq!(
        recv_exactly(&mut sink, EVENT.len()).await,
        EVENT,
        "payload must be forwarded verbatim"
    );
    assert_eq!(link.up.load(Ordering::Relaxed), 1);
    let _ = std::fs::remove_dir_all(&pki.dir);
}

#[tokio::test]
async fn link_survives_outage_and_reconnects_when_server_returns() {
    let pki = mint_pki("reconnect");

    // Learn a port, then take the server DOWN (deterministic outage).
    let addr = bind_sink(&pki, "127.0.0.1:0").await.stop();

    let mut relay = Relay::new(8);
    let mut link = TakLink::new(&link_config(&pki, &addr)).unwrap();

    // Server down: the send fails cleanly and the event stays buffered — no crash,
    // no delivery, link marked down.
    relay.push(bytes::Bytes::from_static(EVENT));
    relay.drain(&mut link).await;
    assert!(
        !relay.is_empty(),
        "event must remain buffered while TAK is down"
    );
    assert_eq!(link.up.load(Ordering::Relaxed), 0);
    assert_eq!(link.reconnects.load(Ordering::Relaxed), 0);

    // Server returns on the SAME port.
    let mut sink = bind_sink(&pki, &addr).await;

    // Relay resumes: retry draining until the buffer clears.
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

    // And the buffered event arrived byte-identical after the outage.
    assert_eq!(recv_exactly(&mut sink, EVENT.len()).await, EVENT);
    let _ = std::fs::remove_dir_all(&pki.dir);
}

/// Full loop: NATS egress subject → relay → TAK sink. Needs a running broker, so
/// it is env-gated and skips cleanly otherwise.
#[tokio::test]
async fn nats_to_tak_full_loop() {
    let Ok(nats_url) = std::env::var("AJAR_TEST_NATS_URL") else {
        eprintln!("skipping nats_to_tak_full_loop (set AJAR_TEST_NATS_URL to run)");
        return;
    };
    let pki = mint_pki("fullloop");
    let mut sink = bind_sink(&pki, "127.0.0.1:0").await;
    let cfg: ajar_tak_egress::EgressConfig = toml::from_str(&format!(
        r#"
        nats_url = "{nats_url}"
        egress_subject = "ajar.egress.cot.test"
        [tak]
        url = "tls://{addr}"
        tls_ca = "{dir}/ca.crt"
        tls_cert = "{dir}/client.crt"
        tls_key = "{dir}/client.key"
        server_name = "localhost"
        "#,
        addr = sink.addr,
        dir = pki.dir.display(),
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
    let _ = std::fs::remove_dir_all(&pki.dir);
}
