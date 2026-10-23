// SPDX-License-Identifier: Apache-2.0
//! The link to TAK: either the TLS stream into a TAK Server's streaming input
//! (default port 8089), mutual TLS with the relay's enrolled client
//! certificate, server-name verification and reconnect-on-error; or, with no
//! server at all, datagrams onto ATAK's mesh SA multicast group, which every
//! TAK client on the same network reads directly.
//!
//! [`TakLink::send`] is deliberately a self-contained, reusable send path —
//! "write these bytes to TAK" — not inlined in the subscribe loop, because
//! the effector-cue delivery (ADR-0024) will later route an authorized signed
//! CoT tasking message through this same transport.
//!
//! TAK's streaming profile parses concatenated CoT XML event-by-event (TAK
//! Protocol v0), and mesh SA takes one CoT event per datagram. Either way the
//! link writes exactly the bytes it is given.

use rustls_pki_types::pem::PemObject;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

use crate::config::TakConfig;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

enum Delivery {
    /// A TAK Server's streaming input, over mutual TLS.
    Tls {
        endpoint: String,
        server_name: ServerName<'static>,
        connector: TlsConnector,
        stream: Option<Box<TlsStream<TcpStream>>>,
    },
    /// One datagram per event to a group or host: ATAK's mesh SA, no server.
    Datagram { socket: UdpSocket, to: SocketAddr },
}

pub struct TakLink {
    delivery: Delivery,
    pub reconnects: Arc<AtomicU64>,
    pub up: Arc<AtomicU64>,
}

impl TakLink {
    pub fn new(cfg: &TakConfig) -> anyhow::Result<TakLink> {
        let delivery = if cfg.is_datagram() {
            Self::datagram(cfg)?
        } else {
            Self::tls(cfg)?
        };
        let up = Arc::new(AtomicU64::new(0));
        if matches!(delivery, Delivery::Datagram { .. }) {
            // A datagram socket has no connection to be down.
            up.store(1, Ordering::Relaxed);
        }
        Ok(TakLink {
            delivery,
            reconnects: Arc::new(AtomicU64::new(0)),
            up,
        })
    }

    fn tls(cfg: &TakConfig) -> anyhow::Result<Delivery> {
        let (ca, cert, key) = cfg.tls_files()?;
        let mut roots = RootCertStore::empty();
        for c in load_certs(ca)? {
            roots
                .add(c)
                .map_err(|e| anyhow::anyhow!("adding CA cert from {ca}: {e}"))?;
        }
        let client_chain = load_certs(cert)?;
        let client_key = load_key(key)?;

        let tls = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(client_chain, client_key)
            .map_err(|e| anyhow::anyhow!("building TLS client auth: {e}"))?;

        let server_name = ServerName::try_from(cfg.sni())
            .map_err(|e| anyhow::anyhow!("invalid TLS server name {:?}: {e}", cfg.sni()))?;

        Ok(Delivery::Tls {
            endpoint: cfg.endpoint().to_string(),
            server_name,
            connector: TlsConnector::from(std::sync::Arc::new(tls)),
            stream: None,
        })
    }

    fn datagram(cfg: &TakConfig) -> anyhow::Result<Delivery> {
        let to: SocketAddr = cfg
            .endpoint()
            .parse()
            .map_err(|e| anyhow::anyhow!("tak.url {:?}: not ip:port: {e}", cfg.url))?;
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        if to.ip().is_multicast() {
            socket.set_multicast_loop_v4(true)?;
            socket.set_multicast_ttl_v4(cfg.multicast_ttl)?;
            if let Some(addr) = &cfg.interface {
                let ip: std::net::Ipv4Addr = addr.parse().map_err(|_| {
                    anyhow::anyhow!("tak.interface {addr:?} is not an IPv4 address")
                })?;
                socket.set_multicast_if_v4(&ip)?;
            }
        }
        socket.set_nonblocking(true)?;
        socket.bind(&SocketAddr::from(([0, 0, 0, 0], 0)).into())?;
        let socket = UdpSocket::from_std(socket.into())?;
        tracing::info!(to = %to, multicast = to.ip().is_multicast(), "TAK datagram delivery");
        Ok(Delivery::Datagram { socket, to })
    }

    /// Write `bytes` to TAK verbatim: onto the authenticated stream,
    /// connecting or reconnecting as needed, or as one datagram. A stream
    /// error drops the connection so the next call reconnects; retries and
    /// buffering are the caller's job.
    pub async fn send(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        if let Delivery::Datagram { socket, to } = &self.delivery {
            return socket.send_to(bytes, *to).await.map(|_| ());
        }
        if matches!(&self.delivery, Delivery::Tls { stream: None, .. }) {
            self.connect().await?;
        }
        let Delivery::Tls {
            endpoint, stream, ..
        } = &mut self.delivery
        else {
            unreachable!("the delivery kind does not change")
        };
        let s = stream.as_mut().expect("connected above");
        let result = async {
            s.write_all(bytes).await?;
            s.flush().await
        }
        .await;
        if let Err(e) = &result {
            tracing::warn!(endpoint = %endpoint, error = %e, "TAK write failed, dropping link");
            *stream = None;
            self.up.store(0, Ordering::Relaxed);
        }
        result
    }

    async fn connect(&mut self) -> std::io::Result<()> {
        let Delivery::Tls {
            endpoint,
            server_name,
            connector,
            stream,
        } = &mut self.delivery
        else {
            return Ok(());
        };
        let attempt = async {
            let tcp = TcpStream::connect(endpoint.as_str()).await?;
            tcp.set_nodelay(true)?;
            connector.connect(server_name.clone(), tcp).await
        };
        match tokio::time::timeout(CONNECT_TIMEOUT, attempt).await {
            Ok(Ok(s)) => {
                tracing::info!(endpoint = %endpoint, "TAK Server connected");
                *stream = Some(Box::new(s));
                self.reconnects.fetch_add(1, Ordering::Relaxed);
                self.up.store(1, Ordering::Relaxed);
                Ok(())
            }
            Ok(Err(e)) => {
                tracing::warn!(endpoint = %endpoint, error = %e, "TAK connect failed");
                self.up.store(0, Ordering::Relaxed);
                Err(e)
            }
            Err(_) => {
                tracing::warn!(endpoint = %endpoint, "TAK connect timed out");
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
    let certs: Result<Vec<_>, _> = CertificateDer::pem_slice_iter(&data).collect();
    let certs = certs.map_err(|e| anyhow::anyhow!("parsing certificates in {path}: {e}"))?;
    if certs.is_empty() {
        anyhow::bail!("no certificates found in {path}");
    }
    Ok(certs)
}

fn load_key(path: &str) -> anyhow::Result<PrivateKeyDer<'static>> {
    let data = std::fs::read(path).map_err(|e| anyhow::anyhow!("reading {path}: {e}"))?;
    PrivateKeyDer::from_pem_slice(&data)
        .map_err(|e| anyhow::anyhow!("parsing private key in {path}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn datagram_delivery_writes_each_event_verbatim_with_no_server() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = receiver.local_addr().unwrap().port();
        let cfg: TakConfig = toml::from_str(&format!("url = \"udp://127.0.0.1:{port}\"")).unwrap();
        let mut link = TakLink::new(&cfg).unwrap();
        assert_eq!(link.up.load(Ordering::Relaxed), 1);
        link.send(b"<event uid='1'/>").await.unwrap();
        link.send(b"<event uid='2'/>").await.unwrap();
        let mut buf = [0u8; 64];
        let (n, _) = receiver.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"<event uid='1'/>");
        let (n, _) = receiver.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"<event uid='2'/>");
        assert_eq!(link.reconnects.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn a_datagram_url_must_be_an_address() {
        let cfg: TakConfig = toml::from_str("url = \"udp://atak.local:6969\"").unwrap();
        assert!(
            TakLink::new(&cfg).is_err(),
            "a host name is refused: datagrams need an address"
        );
    }
}
