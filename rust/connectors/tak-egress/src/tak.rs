// SPDX-License-Identifier: Apache-2.0
//! The link to TAK: mutual TLS into a TAK Server's streaming input, which
//! parses concatenated CoT events (TAK Protocol v0), or one datagram per event,
//! as ATAK's mesh SA multicast expects. The link writes exactly the bytes it is
//! given.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use rustls_pki_types::pem::PemObject;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

use crate::config::TakConfig;

enum Delivery {
    Tls {
        endpoint: String,
        server_name: ServerName<'static>,
        connector: TlsConnector,
        stream: Option<Box<TlsStream<TcpStream>>>,
    },
    Datagram {
        socket: UdpSocket,
        to: SocketAddr,
    },
}

pub struct TakLink {
    delivery: Delivery,
    pub reconnects: Arc<AtomicU64>,
    pub up: Arc<AtomicU64>,
}

impl TakLink {
    pub fn new(cfg: &TakConfig) -> anyhow::Result<TakLink> {
        let delivery = if cfg.is_datagram() {
            let to: SocketAddr = cfg
                .endpoint()
                .parse()
                .with_context(|| format!("tak.url {:?}: not ip:port", cfg.url))?;
            let socket = socket2::Socket::new(
                socket2::Domain::IPV4,
                socket2::Type::DGRAM,
                Some(socket2::Protocol::UDP),
            )?;
            if to.ip().is_multicast() {
                socket.set_multicast_loop_v4(true)?;
                socket.set_multicast_ttl_v4(cfg.multicast_ttl)?;
                if let Some(addr) = &cfg.interface {
                    let ip: Ipv4Addr = addr.parse().map_err(|_| {
                        anyhow::anyhow!("tak.interface {addr:?} is not an IPv4 address")
                    })?;
                    socket.set_multicast_if_v4(&ip)?;
                }
            }
            socket.set_nonblocking(true)?;
            socket.bind(&SocketAddr::from(([0, 0, 0, 0], 0)).into())?;
            let socket = UdpSocket::from_std(socket.into())?;
            tracing::info!(to = %to, multicast = to.ip().is_multicast(), "TAK datagram delivery");
            Delivery::Datagram { socket, to }
        } else {
            let (ca, cert, key) = cfg.tls_files()?;
            let mut roots = RootCertStore::empty();
            for c in load_certs(ca)? {
                roots
                    .add(c)
                    .with_context(|| format!("adding CA cert from {ca}"))?;
            }
            let key_pem = std::fs::read(key).with_context(|| format!("reading {key}"))?;
            let client_key = PrivateKeyDer::from_pem_slice(&key_pem)
                .with_context(|| format!("parsing private key in {key}"))?;
            let tls = ClientConfig::builder()
                .with_root_certificates(roots)
                .with_client_auth_cert(load_certs(cert)?, client_key)
                .context("building TLS client auth")?;
            let sni = cfg.sni();
            let server_name = ServerName::try_from(sni.clone())
                .with_context(|| format!("invalid TLS server name {sni:?}"))?;
            Delivery::Tls {
                endpoint: cfg.endpoint().to_string(),
                server_name,
                connector: TlsConnector::from(Arc::new(tls)),
                stream: None,
            }
        };
        // A datagram socket has no connection to be down.
        let up = Arc::new(AtomicU64::new(u64::from(cfg.is_datagram())));
        Ok(TakLink {
            delivery,
            reconnects: Arc::new(AtomicU64::new(0)),
            up,
        })
    }

    /// Write `bytes` to TAK verbatim, connecting first if the stream is down.
    /// A stream error drops the connection so the next call reconnects;
    /// retries and buffering are the caller's job.
    pub async fn send(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        let (endpoint, server_name, connector, stream) = match &mut self.delivery {
            Delivery::Datagram { socket, to } => {
                return socket.send_to(bytes, *to).await.map(|_| ());
            }
            Delivery::Tls {
                endpoint,
                server_name,
                connector,
                stream,
            } => (endpoint, server_name, connector, stream),
        };
        let s = match stream {
            Some(s) => s,
            None => match connect(endpoint, server_name, connector).await {
                Ok(s) => {
                    tracing::info!(endpoint = %endpoint, "TAK Server connected");
                    self.reconnects.fetch_add(1, Ordering::Relaxed);
                    self.up.store(1, Ordering::Relaxed);
                    stream.insert(Box::new(s))
                }
                Err(e) => {
                    tracing::warn!(endpoint = %endpoint, error = %e, "TAK connect failed");
                    self.up.store(0, Ordering::Relaxed);
                    return Err(e);
                }
            },
        };
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
}

async fn connect(
    endpoint: &str,
    server_name: &ServerName<'static>,
    connector: &TlsConnector,
) -> std::io::Result<TlsStream<TcpStream>> {
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
    let attempt = async {
        let tcp = TcpStream::connect(endpoint).await?;
        tcp.set_nodelay(true)?;
        connector.connect(server_name.clone(), tcp).await
    };
    tokio::time::timeout(CONNECT_TIMEOUT, attempt)
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("timed out after {CONNECT_TIMEOUT:?}"),
            )
        })?
}

fn load_certs(path: &str) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let data = std::fs::read(path).with_context(|| format!("reading {path}"))?;
    let certs = CertificateDer::pem_slice_iter(&data)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("parsing certificates in {path}"))?;
    if certs.is_empty() {
        anyhow::bail!("no certificates found in {path}");
    }
    Ok(certs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn datagram_delivery_is_verbatim() {
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
    fn datagram_url_must_be_an_address() {
        let cfg: TakConfig = toml::from_str("url = \"udp://atak.local:6969\"").unwrap();
        assert!(
            TakLink::new(&cfg).is_err(),
            "a host name is refused: datagrams need an address"
        );
    }
}
