// SPDX-License-Identifier: Apache-2.0
//! The TLS link to a TAK Server's streaming input (default port 8089): mutual
//! TLS with the relay's enrolled client certificate, server-name verification,
//! and reconnect-on-error.
//!
//! [`TakLink::send`] is deliberately a self-contained, reusable send path —
//! "write these bytes to the authenticated TAK stream" — not inlined in the
//! subscribe loop, because the effector-cue delivery (ADR-0024) will later route
//! an authorized signed CoT tasking message through this same transport.
//!
//! TAK's streaming profile parses concatenated CoT XML event-by-event (TAK
//! Protocol v0). Optional protobuf-v1 negotiation is a possible later addition;
//! today the link writes exactly the bytes it is given.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

use crate::config::TakConfig;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// A reconnecting mutual-TLS client connection to one TAK Server.
pub struct TakLink {
    endpoint: String,
    server_name: ServerName<'static>,
    connector: TlsConnector,
    stream: Option<TlsStream<TcpStream>>,
    /// Successful (re)connects to the TAK Server.
    pub reconnects: Arc<AtomicU64>,
    /// Link state gauge: 1 = connected, 0 = down.
    pub up: Arc<AtomicU64>,
}

impl TakLink {
    /// Build the link from config: loads the CA bundle, this relay's client
    /// certificate chain and key, and resolves the server name to verify.
    /// Connection itself is lazy — the first [`TakLink::send`] opens it.
    pub fn new(cfg: &TakConfig) -> anyhow::Result<TakLink> {
        let mut roots = RootCertStore::empty();
        for cert in load_certs(&cfg.tls_ca)? {
            roots
                .add(cert)
                .map_err(|e| anyhow::anyhow!("adding CA cert from {}: {e}", cfg.tls_ca))?;
        }
        let client_chain = load_certs(&cfg.tls_cert)?;
        let client_key = load_key(&cfg.tls_key)?;

        let tls = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(client_chain, client_key)
            .map_err(|e| anyhow::anyhow!("building TLS client auth: {e}"))?;

        let server_name = ServerName::try_from(cfg.sni())
            .map_err(|e| anyhow::anyhow!("invalid TLS server name {:?}: {e}", cfg.sni()))?;

        Ok(TakLink {
            endpoint: cfg.endpoint().to_string(),
            server_name,
            connector: TlsConnector::from(std::sync::Arc::new(tls)),
            stream: None,
            reconnects: Arc::new(AtomicU64::new(0)),
            up: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Write `bytes` to the TAK stream verbatim, connecting (or reconnecting)
    /// first if needed. One failed attempt returns `Err` promptly — pacing and
    /// buffering are the caller's job — and drops the connection so the next
    /// call starts fresh.
    pub async fn send(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        if self.stream.is_none() {
            self.connect().await?;
        }
        let stream = self.stream.as_mut().expect("connected above");
        let result = async {
            stream.write_all(bytes).await?;
            stream.flush().await
        }
        .await;
        if let Err(e) = &result {
            tracing::warn!(endpoint = %self.endpoint, error = %e, "TAK write failed, dropping link");
            self.stream = None;
            self.up.store(0, Ordering::Relaxed);
        }
        result
    }

    async fn connect(&mut self) -> std::io::Result<()> {
        let attempt = async {
            let tcp = TcpStream::connect(&self.endpoint).await?;
            tcp.set_nodelay(true)?;
            self.connector.connect(self.server_name.clone(), tcp).await
        };
        match tokio::time::timeout(CONNECT_TIMEOUT, attempt).await {
            Ok(Ok(stream)) => {
                tracing::info!(endpoint = %self.endpoint, "TAK Server connected");
                self.stream = Some(stream);
                self.reconnects.fetch_add(1, Ordering::Relaxed);
                self.up.store(1, Ordering::Relaxed);
                Ok(())
            }
            Ok(Err(e)) => {
                tracing::warn!(endpoint = %self.endpoint, error = %e, "TAK connect failed");
                self.up.store(0, Ordering::Relaxed);
                Err(e)
            }
            Err(_) => {
                tracing::warn!(endpoint = %self.endpoint, "TAK connect timed out");
                self.up.store(0, Ordering::Relaxed);
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "TAK connect timed out",
                ))
            }
        }
    }
}

fn load_certs(path: &str) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let data = std::fs::read(path).map_err(|e| anyhow::anyhow!("reading {path}: {e}"))?;
    let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut data.as_slice()).collect();
    let certs = certs.map_err(|e| anyhow::anyhow!("parsing certificates in {path}: {e}"))?;
    if certs.is_empty() {
        anyhow::bail!("no certificates found in {path}");
    }
    Ok(certs)
}

fn load_key(path: &str) -> anyhow::Result<PrivateKeyDer<'static>> {
    let data = std::fs::read(path).map_err(|e| anyhow::anyhow!("reading {path}: {e}"))?;
    rustls_pemfile::private_key(&mut data.as_slice())
        .map_err(|e| anyhow::anyhow!("parsing private key in {path}: {e}"))?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {path}"))
}
