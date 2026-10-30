// SPDX-License-Identifier: Apache-2.0
//! The fusion-node acceptor, the DMM in BSI Flex 335 terms. A sensor connects,
//! sends a `Registration` and reports nothing until it has a
//! `RegistrationAck`, so this source owns the connections: it answers each
//! registration and forwards every message unchanged, the registration
//! included, through a bounded channel the runtime drains.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ajar_connector_common::FrameSource;
use ajar_sapient_wire::v2::sapient_message::Content;
use ajar_sapient_wire::{v2, ReadError};
use anyhow::Context;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

/// Frames buffered toward the runtime. A full channel slows the sensors
/// rather than growing memory.
const CHANNEL_FRAMES: usize = 1024;

#[derive(Default)]
pub struct DmmCounters {
    /// Registrations acknowledged.
    pub registrations: Arc<AtomicU64>,
    /// Connections closed for a frame above the size bound.
    pub bad_framing: Arc<AtomicU64>,
}

pub struct DmmSource {
    rx: mpsc::Receiver<Vec<u8>>,
    bind: String,
    pub counters: Arc<DmmCounters>,
}

impl DmmSource {
    /// Bind eagerly, so a port in use fails at start-up. `node_id` is carried
    /// in every acknowledgement.
    pub async fn bind(bind: &str, node_id: String) -> anyhow::Result<Self> {
        let listener = TcpListener::bind(bind)
            .await
            .with_context(|| format!("binding {bind}"))?;
        let (tx, rx) = mpsc::channel(CHANNEL_FRAMES);
        let counters = Arc::new(DmmCounters::default());
        tokio::spawn(accept_loop(listener, node_id, tx, counters.clone()));
        Ok(Self {
            rx,
            bind: bind.to_string(),
            counters,
        })
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
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
}

/// One sensor's connection, until it disconnects or sends a frame above the
/// size bound.
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
    let mut held = Vec::with_capacity(8192);
    loop {
        let payload = match ajar_sapient_wire::read_frame(&mut stream, &mut held).await {
            Ok(payload) => payload,
            Err(ReadError::Closed) => {
                tracing::info!(%peer, "sapient node disconnected");
                return;
            }
            Err(ReadError::TooLong(n)) => {
                counters.bad_framing.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(%peer, declared = n, "frame above the size bound");
                return;
            }
            Err(ReadError::Io(e)) => {
                tracing::warn!(%peer, error = %e, "read failed");
                return;
            }
        };
        if let Some(ack) = registration_ack(&payload, &node_id) {
            if let Err(e) = stream.write_all(&ack).await {
                tracing::warn!(%peer, error = %e, "sending registration ack failed");
                return;
            }
            counters.registrations.fetch_add(1, Ordering::Relaxed);
            tracing::info!(%peer, "sapient node registered");
        }
        if tx.send(payload).await.is_err() {
            return;
        }
    }
}

/// The framed acknowledgement to send if `payload` is a registration. A
/// message that does not decode is left for the parser to report.
fn registration_ack(payload: &[u8], node_id: &str) -> Option<Vec<u8>> {
    let message = ajar_sapient_wire::decode(payload).ok()?;
    if !matches!(message.content, Some(Content::Registration(_))) {
        return None;
    }
    let ack = v2::SapientMessage {
        timestamp: Some(ajar_sapient_wire::now()),
        node_id: Some(node_id.to_string()),
        destination_id: message.node_id,
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
    use ajar_sapient_wire::PREFIX_LEN;
    use tokio::io::AsyncReadExt;

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
        // Split so the acceptor sees a partial frame first.
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
    async fn oversized_frame_closes_the_connection() {
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
