// SPDX-License-Identifier: Apache-2.0
//! The fusion-node acceptor: sensors connect in over TCP, register, and are
//! acknowledged; everything they send then flows to the parser.
//!
//! BSI Flex 335 calls the fusion node's message handler the DMM. A sensor
//! opens a connection, sends a `Registration`, and reports nothing until it
//! has a `RegistrationAck`. The runtime's `tcp-server` transport only reads,
//! so this source owns the connections: it reads frames in the standard's
//! framing, answers each registration, and forwards every message, the
//! registration included, through a bounded channel the runtime drains.
//!
//! Nothing is interpreted here beyond "is this a registration": the parser
//! sees the same bytes the sensor sent.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use ajar_connector_common::FrameSource;
use ajar_sapient_wire::v2::sapient_message::Content;
use ajar_sapient_wire::{v2, FrameError, MAX_MESSAGE_LEN, PREFIX_LEN};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

/// Frames buffered between the acceptor and the runtime. A full channel slows
/// the sensors rather than growing memory.
const CHANNEL_FRAMES: usize = 1024;

/// Counters the acceptor publishes on `/metrics`.
#[derive(Default)]
pub struct DmmCounters {
    /// Registrations acknowledged, since start.
    pub registrations: Arc<AtomicU64>,
    /// Connections that ended with bytes that were not the standard's framing.
    pub bad_framing: Arc<AtomicU64>,
}

/// The accepting source. Hand it to the runtime as the frame source.
pub struct DmmSource {
    rx: mpsc::Receiver<Vec<u8>>,
    bind: String,
    counters: Arc<DmmCounters>,
}

impl DmmSource {
    /// Bind `bind` and start accepting sensors. Binding is eager, so a port in
    /// use fails at start-up. `node_id` is this fusion node's identity, carried
    /// in every acknowledgement.
    pub async fn bind(bind: &str, node_id: String) -> anyhow::Result<Self> {
        let listener = TcpListener::bind(bind)
            .await
            .map_err(|e| anyhow::anyhow!("binding {bind}: {e}"))?;
        let (tx, rx) = mpsc::channel(CHANNEL_FRAMES);
        let counters = Arc::new(DmmCounters::default());
        tokio::spawn(accept_loop(listener, node_id, tx, counters.clone()));
        Ok(Self {
            rx,
            bind: bind.to_string(),
            counters,
        })
    }

    /// The counters, for the runtime's metrics endpoint.
    pub fn counters(&self) -> Arc<DmmCounters> {
        self.counters.clone()
    }
}

#[async_trait::async_trait]
impl FrameSource for DmmSource {
    async fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.rx.recv().await {
            Some(frame) => {
                let n = frame.len().min(buf.len());
                buf[..n].copy_from_slice(&frame[..n]);
                Ok(n)
            }
            None => Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "sapient accept loop ended",
            )),
        }
    }

    fn describe(&self) -> String {
        format!("sapient fusion node on {}", self.bind)
    }
}

async fn accept_loop(
    listener: TcpListener,
    node_id: String,
    tx: mpsc::Sender<Vec<u8>>,
    counters: Arc<DmmCounters>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                tracing::info!(%peer, "sapient node connected");
                tokio::spawn(connection_loop(
                    stream,
                    node_id.clone(),
                    tx.clone(),
                    counters.clone(),
                ));
            }
            Err(e) => {
                tracing::warn!(error = %e, "accept failed, retrying");
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        }
    }
}

/// One sensor's connection: read frames, acknowledge its registration, and
/// forward every message. Ends when the sensor disconnects or sends bytes
/// that are not the standard's framing.
async fn connection_loop(
    mut stream: TcpStream,
    node_id: String,
    tx: mpsc::Sender<Vec<u8>>,
    counters: Arc<DmmCounters>,
) {
    let peer = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".into());
    let mut held: Vec<u8> = Vec::with_capacity(8192);
    let mut chunk = [0u8; 8192];
    loop {
        // Deliver every whole frame already held.
        loop {
            match ajar_sapient_wire::unframe(&held) {
                Ok((payload, rest)) => {
                    let payload = payload.to_vec();
                    let consumed = held.len() - rest.len();
                    held.drain(..consumed);
                    if let Some(ack) = registration_ack(&payload, &node_id) {
                        if let Err(e) = stream.write_all(&ack).await {
                            tracing::warn!(%peer, error = %e, "sending registration ack failed");
                            return;
                        }
                        counters.registrations.fetch_add(1, Ordering::Relaxed);
                        tracing::info!(%peer, "sapient node registered and acknowledged");
                    }
                    if tx.send(payload).await.is_err() {
                        return; // the runtime is gone
                    }
                }
                Err(FrameError::NeedPrefix) | Err(FrameError::Incomplete { .. }) => break,
                Err(FrameError::TooLong(n)) => {
                    counters.bad_framing.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(%peer, declared = n, "frame above the size bound; closing");
                    return;
                }
            }
        }
        if held.len() > MAX_MESSAGE_LEN + PREFIX_LEN {
            counters.bad_framing.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(%peer, "no frame boundary within the size bound; closing");
            return;
        }
        match stream.read(&mut chunk).await {
            Ok(0) => {
                tracing::info!(%peer, "sapient node disconnected");
                return;
            }
            Ok(n) => held.extend_from_slice(&chunk[..n]),
            Err(e) => {
                tracing::warn!(%peer, error = %e, "read failed");
                return;
            }
        }
    }
}

/// The framed acknowledgement to send if `payload` is a registration, else
/// `None`. A message that does not decode is not a registration; the parser
/// reports it.
fn registration_ack(payload: &[u8], node_id: &str) -> Option<Vec<u8>> {
    let message = ajar_sapient_wire::decode(payload).ok()?;
    if !matches!(message.content, Some(Content::Registration(_))) {
        return None;
    }
    let ack = v2::SapientMessage {
        timestamp: Some(ajar_sapient_wire::now()),
        node_id: Some(node_id.to_string()),
        destination_id: message.node_id.clone(),
        content: Some(Content::RegistrationAck(v2::RegistrationAck {
            acceptance: Some(true),
            ack_response_reason: Vec::new(),
        })),
        additional_information: None,
    };
    Some(ajar_sapient_wire::frame(&ajar_sapient_wire::encode(&ack)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpStream;

    fn registration(node: &str) -> Vec<u8> {
        let m = v2::SapientMessage {
            timestamp: Some(ajar_sapient_wire::now()),
            node_id: Some(node.into()),
            destination_id: None,
            content: Some(Content::Registration(v2::Registration {
                icd_version: Some(ajar_sapient_wire::ICD_VERSION_V2.into()),
                name: Some("bench radar".into()),
                ..Default::default()
            })),
            additional_information: None,
        };
        ajar_sapient_wire::frame(&ajar_sapient_wire::encode(&m))
    }

    #[tokio::test]
    async fn a_registration_is_acknowledged_and_forwarded() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, mut rx) = mpsc::channel(8);
        let counters = Arc::new(DmmCounters::default());
        tokio::spawn(accept_loop(
            listener,
            "fusion-1".into(),
            tx,
            counters.clone(),
        ));

        let mut sensor = TcpStream::connect(addr).await.unwrap();
        let reg = registration("sensor-7");
        // Split the write so the acceptor sees a partial frame first.
        sensor.write_all(&reg[..3]).await.unwrap();
        sensor.write_all(&reg[3..]).await.unwrap();

        let forwarded = rx.recv().await.unwrap();
        assert_eq!(forwarded, reg[PREFIX_LEN..]);

        let mut ack = vec![0u8; 256];
        let n = sensor.read(&mut ack).await.unwrap();
        let (payload, rest) = ajar_sapient_wire::unframe(&ack[..n]).unwrap();
        assert!(rest.is_empty());
        let ack = ajar_sapient_wire::decode(payload).unwrap();
        assert_eq!(ack.node_id.as_deref(), Some("fusion-1"));
        assert_eq!(ack.destination_id.as_deref(), Some("sensor-7"));
        assert!(matches!(
            ack.content,
            Some(Content::RegistrationAck(v2::RegistrationAck {
                acceptance: Some(true),
                ..
            }))
        ));
        assert_eq!(counters.registrations.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn bytes_that_are_not_the_framing_close_the_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, _rx) = mpsc::channel(8);
        let counters = Arc::new(DmmCounters::default());
        tokio::spawn(accept_loop(
            listener,
            "fusion-1".into(),
            tx,
            counters.clone(),
        ));

        let mut sensor = TcpStream::connect(addr).await.unwrap();
        sensor
            .write_all(&[0xff, 0xff, 0xff, 0xff, 1])
            .await
            .unwrap();
        let mut buf = [0u8; 8];
        let n = sensor.read(&mut buf).await.unwrap_or(0);
        assert_eq!(n, 0, "the acceptor closes rather than waits");
        assert_eq!(counters.bad_framing.load(Ordering::Relaxed), 1);
    }
}
