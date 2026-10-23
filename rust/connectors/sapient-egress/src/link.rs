// SPDX-License-Identifier: Apache-2.0
//! The connection to the fusion node: connect, register, be acknowledged,
//! then send reports and answer what comes back. Drops and reconnects on
//! any error; the caller buffers and retries.
//!
//! BSI Flex 335 makes registration the first thing on a new connection and
//! says a node reports nothing until its registration is acknowledged. A
//! rejection carries reasons, which are surfaced in the error so an operator
//! sees what the fusion node objected to.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ajar_sapient_wire::v2::sapient_message::Content;
use ajar_sapient_wire::{v2, FrameError, MAX_MESSAGE_LEN, PREFIX_LEN};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

use crate::report::Node;

/// How long a fusion node has to accept a connection and to acknowledge a
/// registration before the attempt is given up and retried.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const ACK_TIMEOUT: Duration = Duration::from_secs(10);

pub struct FusionLink {
    addr: String,
    node: Node,
    reader: Option<OwnedReadHalf>,
    writer: Option<OwnedWriteHalf>,
    held: Vec<u8>,
    /// 1 while registered and connected, 0 otherwise. A gauge for `/metrics`.
    pub up: Arc<AtomicU64>,
    /// Connections made after the first, since start.
    pub reconnects: Arc<AtomicU64>,
    /// Registrations the fusion node rejected, since start.
    pub rejected_registrations: Arc<AtomicU64>,
    ever_connected: bool,
}

impl FusionLink {
    pub fn new(addr: &str, node: Node) -> FusionLink {
        FusionLink {
            addr: addr.to_string(),
            node,
            reader: None,
            writer: None,
            held: Vec::new(),
            up: Arc::new(AtomicU64::new(0)),
            reconnects: Arc::new(AtomicU64::new(0)),
            rejected_registrations: Arc::new(AtomicU64::new(0)),
            ever_connected: false,
        }
    }

    pub fn connected(&self) -> bool {
        self.writer.is_some()
    }

    /// Connect and register if not already; an error leaves the link down.
    pub async fn ensure_registered(&mut self) -> std::io::Result<()> {
        if self.connected() {
            return Ok(());
        }
        let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&self.addr))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timed out")
            })??;
        stream.set_nodelay(true)?;
        let (reader, writer) = stream.into_split();
        self.reader = Some(reader);
        self.writer = Some(writer);
        self.held.clear();
        if self.ever_connected {
            self.reconnects.fetch_add(1, Ordering::Relaxed);
        }
        self.ever_connected = true;

        let registration = self.node.registration();
        if let Err(e) = self.write(&registration).await {
            self.drop_connection();
            return Err(e);
        }
        let ack = match tokio::time::timeout(ACK_TIMEOUT, self.await_ack()).await {
            Ok(Ok(ack)) => ack,
            Ok(Err(e)) => {
                self.drop_connection();
                return Err(e);
            }
            Err(_) => {
                self.drop_connection();
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "no registration acknowledgement within 10 s",
                ));
            }
        };
        if ack.acceptance != Some(true) {
            self.rejected_registrations.fetch_add(1, Ordering::Relaxed);
            self.drop_connection();
            let reasons = if ack.ack_response_reason.is_empty() {
                "no reason given".to_string()
            } else {
                ack.ack_response_reason.join("; ")
            };
            return Err(std::io::Error::other(format!(
                "the fusion node rejected this node's registration: {reasons}"
            )));
        }
        self.up.store(1, Ordering::Relaxed);
        tracing::info!(fusion_node = %self.addr, node_id = %self.node.node_id, "registered with the fusion node");
        Ok(())
    }

    /// Read messages until the registration acknowledgement arrives.
    async fn await_ack(&mut self) -> std::io::Result<v2::RegistrationAck> {
        loop {
            let message = self.read_message().await?;
            if let Some(Content::RegistrationAck(ack)) = message.content {
                return Ok(ack);
            }
        }
    }

    /// Send one message, framed. An error drops the connection so the next
    /// call reconnects and re-registers; the caller keeps the message.
    pub async fn send(&mut self, message: &v2::SapientMessage) -> std::io::Result<()> {
        self.ensure_registered().await?;
        if let Err(e) = self.write(message).await {
            self.drop_connection();
            return Err(e);
        }
        Ok(())
    }

    async fn write(&mut self, message: &v2::SapientMessage) -> std::io::Result<()> {
        let bytes = ajar_sapient_wire::frame(&ajar_sapient_wire::encode(message));
        let writer = self.writer.as_mut().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotConnected, "not connected")
        })?;
        writer.write_all(&bytes).await?;
        writer.flush().await
    }

    /// The next message from the fusion node. Only meaningful while
    /// connected; pending forever otherwise, so a `select!` branch guards it
    /// with [`FusionLink::connected`].
    pub async fn next_inbound(&mut self) -> std::io::Result<v2::SapientMessage> {
        match self.read_message().await {
            Ok(m) => Ok(m),
            Err(e) => {
                self.drop_connection();
                Err(e)
            }
        }
    }

    async fn read_message(&mut self) -> std::io::Result<v2::SapientMessage> {
        let reader = self.reader.as_mut().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotConnected, "not connected")
        })?;
        let mut chunk = [0u8; 8192];
        loop {
            match ajar_sapient_wire::unframe(&self.held) {
                Ok((payload, rest)) => {
                    let message = ajar_sapient_wire::decode(payload).map_err(|e| {
                        std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
                    });
                    let consumed = self.held.len() - rest.len();
                    self.held.drain(..consumed);
                    return message;
                }
                Err(FrameError::TooLong(n)) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("frame of {n} bytes from the fusion node is above the bound"),
                    ));
                }
                Err(FrameError::NeedPrefix) | Err(FrameError::Incomplete { .. }) => {}
            }
            if self.held.len() > MAX_MESSAGE_LEN + PREFIX_LEN {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "no frame boundary within the size bound",
                ));
            }
            let n = reader.read(&mut chunk).await?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "the fusion node closed the connection",
                ));
            }
            self.held.extend_from_slice(&chunk[..n]);
        }
    }

    /// Answer an inbound message: a task is refused, anything else noted.
    /// Returns whether a reply was sent.
    pub async fn answer(&mut self, message: &v2::SapientMessage) -> std::io::Result<bool> {
        match &message.content {
            Some(Content::Task(task)) => {
                let id = task.task_id.clone().unwrap_or_default();
                tracing::info!(task_id = %id, "task from the fusion node refused: this node takes no tasks");
                let ack = self.node.task_rejected(&id, message.node_id.as_deref());
                self.send(&ack).await?;
                Ok(true)
            }
            Some(Content::Error(e)) => {
                tracing::warn!(reasons = ?e.error_message, "the fusion node reported an error on a message of ours");
                Ok(false)
            }
            _ => Ok(false),
        }
    }

    pub fn drop_connection(&mut self) {
        if self.connected() {
            tracing::warn!(fusion_node = %self.addr, "connection to the fusion node dropped; will reconnect and re-register");
        }
        self.reader = None;
        self.writer = None;
        self.held.clear();
        self.up.store(0, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::EgressConfig;
    use tokio::net::TcpListener;

    const KEY: &str = "e28a89f1c0d2b3a4958677665544332211ffeeddccbbaa99887766554433221100";

    fn node() -> Node {
        let cfg: EgressConfig = toml::from_str(&format!(
            "nats_url = \"nats://127.0.0.1:4222\"\negress_verifying_key = \"{KEY}\"\n[sapient]\nfusion_node = \"x:1\"\nnode_id = \"ajar-node\""
        ))
        .unwrap();
        Node::from_config(&cfg)
    }

    /// A fusion node that reads one framed message and returns it.
    async fn read_one(stream: &mut TcpStream) -> v2::SapientMessage {
        let mut held = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            if let Ok((payload, _)) = ajar_sapient_wire::unframe(&held) {
                return ajar_sapient_wire::decode(payload).unwrap();
            }
            let n = stream.read(&mut chunk).await.unwrap();
            assert!(n > 0, "node closed before sending");
            held.extend_from_slice(&chunk[..n]);
        }
    }

    fn ack(accept: bool, reasons: &[&str]) -> Vec<u8> {
        let m = v2::SapientMessage {
            timestamp: Some(ajar_sapient_wire::now()),
            node_id: Some("fusion".into()),
            destination_id: Some("ajar-node".into()),
            content: Some(Content::RegistrationAck(v2::RegistrationAck {
                acceptance: Some(accept),
                ack_response_reason: reasons.iter().map(|r| r.to_string()).collect(),
            })),
            additional_information: None,
        };
        ajar_sapient_wire::frame(&ajar_sapient_wire::encode(&m))
    }

    #[tokio::test]
    async fn registers_then_sends_and_answers_a_task() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let fusion = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let reg = read_one(&mut s).await;
            assert!(matches!(reg.content, Some(Content::Registration(_))));
            s.write_all(&ack(true, &[])).await.unwrap();
            let status = read_one(&mut s).await;
            assert!(matches!(status.content, Some(Content::StatusReport(_))));
            // Task the node; expect a rejection.
            let task = v2::SapientMessage {
                timestamp: Some(ajar_sapient_wire::now()),
                node_id: Some("fusion".into()),
                destination_id: Some("ajar-node".into()),
                content: Some(Content::Task(v2::Task {
                    task_id: Some("01J9A0TASK00000000000000001".into()),
                    control: Some(v2::task::Control::Start as i32),
                    ..Default::default()
                })),
                additional_information: None,
            };
            s.write_all(&ajar_sapient_wire::frame(&ajar_sapient_wire::encode(&task)))
                .await
                .unwrap();
            let reply = read_one(&mut s).await;
            match reply.content {
                Some(Content::TaskAck(a)) => {
                    assert_eq!(
                        a.task_status,
                        Some(v2::task_ack::TaskStatus::Rejected as i32)
                    );
                    assert_eq!(a.task_id.as_deref(), Some("01J9A0TASK00000000000000001"));
                }
                other => panic!("{other:?}"),
            }
        });

        let node = node();
        let mut link = FusionLink::new(&addr.to_string(), node.clone());
        link.ensure_registered().await.unwrap();
        assert_eq!(link.up.load(Ordering::Relaxed), 1);
        link.send(&node.status(true)).await.unwrap();
        let inbound = link.next_inbound().await.unwrap();
        assert!(link.answer(&inbound).await.unwrap());
        fusion.await.unwrap();
    }

    #[tokio::test]
    async fn a_rejected_registration_is_an_error_with_the_reasons() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let _ = read_one(&mut s).await;
            s.write_all(&ack(false, &["unknown node type", "no capability"]))
                .await
                .unwrap();
        });
        let mut link = FusionLink::new(&addr.to_string(), node());
        let err = link.ensure_registered().await.unwrap_err();
        assert!(
            err.to_string().contains("unknown node type; no capability"),
            "{err}"
        );
        assert!(!link.connected());
        assert_eq!(link.rejected_registrations.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn a_dropped_connection_reconnects_and_re_registers_on_the_next_send() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let fusion = tokio::spawn(async move {
            // First connection: accept the registration, then hang up.
            let (mut s, _) = listener.accept().await.unwrap();
            let _ = read_one(&mut s).await;
            s.write_all(&ack(true, &[])).await.unwrap();
            drop(s);
            // Second connection: a fresh registration must arrive first.
            let (mut s, _) = listener.accept().await.unwrap();
            let reg = read_one(&mut s).await;
            assert!(matches!(reg.content, Some(Content::Registration(_))));
            s.write_all(&ack(true, &[])).await.unwrap();
            let status = read_one(&mut s).await;
            assert!(matches!(status.content, Some(Content::StatusReport(_))));
        });
        let node = node();
        let mut link = FusionLink::new(&addr.to_string(), node.clone());
        link.ensure_registered().await.unwrap();
        // The peer hung up: the next read fails and drops the link.
        assert!(link.next_inbound().await.is_err());
        assert!(!link.connected());
        // A send reconnects, re-registers, then delivers.
        link.send(&node.status(true)).await.unwrap();
        assert_eq!(link.reconnects.load(Ordering::Relaxed), 1);
        fusion.await.unwrap();
    }

    #[tokio::test]
    async fn nobody_listening_is_an_error_not_a_hang() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let mut link = FusionLink::new(&addr.to_string(), node());
        assert!(link.ensure_registered().await.is_err());
        assert_eq!(link.up.load(Ordering::Relaxed), 0);
    }
}
