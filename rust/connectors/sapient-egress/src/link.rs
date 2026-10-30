// SPDX-License-Identifier: Apache-2.0
//! The connection to the fusion node. BSI Flex 335 makes registration the
//! first message on a connection, and a node reports nothing until it is
//! acknowledged. Any error drops the connection; the next send reconnects and
//! re-registers.

use std::io::{self, ErrorKind};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ajar_sapient_wire::v2;
use ajar_sapient_wire::v2::sapient_message::Content;
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

use crate::report::Node;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const ACK_TIMEOUT: Duration = Duration::from_secs(10);

pub struct FusionLink {
    addr: String,
    node: Node,
    reader: Option<OwnedReadHalf>,
    writer: Option<OwnedWriteHalf>,
    held: Vec<u8>,
    /// Gauge: 1 while registered and connected.
    pub up: Arc<AtomicU64>,
    /// Connections made after the first.
    pub reconnects: Arc<AtomicU64>,
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
    pub async fn ensure_registered(&mut self) -> io::Result<()> {
        if self.connected() {
            return Ok(());
        }
        let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&self.addr))
            .await
            .map_err(|_| io::Error::new(ErrorKind::TimedOut, "connect timed out"))??;
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
                return Err(io::Error::new(
                    ErrorKind::TimedOut,
                    format!("no registration acknowledgement within {ACK_TIMEOUT:?}"),
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
            return Err(io::Error::other(format!(
                "the fusion node rejected this node's registration: {reasons}"
            )));
        }
        self.up.store(1, Ordering::Relaxed);
        tracing::info!(fusion_node = %self.addr, node_id = %self.node.node_id, "registered with the fusion node");
        Ok(())
    }

    /// Read messages until the registration acknowledgement arrives.
    async fn await_ack(&mut self) -> io::Result<v2::RegistrationAck> {
        loop {
            let message = self.read_message().await?;
            if let Some(Content::RegistrationAck(ack)) = message.content {
                return Ok(ack);
            }
        }
    }

    /// Send one message. On an error the caller keeps the message.
    pub async fn send(&mut self, message: &v2::SapientMessage) -> io::Result<()> {
        self.ensure_registered().await?;
        if let Err(e) = self.write(message).await {
            self.drop_connection();
            return Err(e);
        }
        Ok(())
    }

    async fn write(&mut self, message: &v2::SapientMessage) -> io::Result<()> {
        let bytes = ajar_sapient_wire::frame(&ajar_sapient_wire::encode(message));
        let writer = self
            .writer
            .as_mut()
            .ok_or_else(|| io::Error::from(ErrorKind::NotConnected))?;
        writer.write_all(&bytes).await?;
        writer.flush().await
    }

    /// The next message from the fusion node; a `select!` branch guards it
    /// with [`FusionLink::connected`].
    pub async fn next_inbound(&mut self) -> io::Result<v2::SapientMessage> {
        match self.read_message().await {
            Ok(m) => Ok(m),
            Err(e) => {
                self.drop_connection();
                Err(e)
            }
        }
    }

    async fn read_message(&mut self) -> io::Result<v2::SapientMessage> {
        let reader = self
            .reader
            .as_mut()
            .ok_or_else(|| io::Error::from(ErrorKind::NotConnected))?;
        let payload = ajar_sapient_wire::read_frame(reader, &mut self.held).await?;
        ajar_sapient_wire::decode(&payload).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))
    }

    /// Refuse a task, note an error. Returns whether a reply was sent.
    pub async fn answer(&mut self, message: &v2::SapientMessage) -> io::Result<bool> {
        match &message.content {
            Some(Content::Task(task)) => {
                let id = task.task_id.as_deref().unwrap_or_default();
                tracing::info!(task_id = %id, "task from the fusion node refused");
                let ack = self.node.task_rejected(id, message.node_id.as_deref());
                self.send(&ack).await?;
                Ok(true)
            }
            Some(Content::Error(e)) => {
                tracing::warn!(reasons = ?e.error_message, "fusion node reported an error");
                Ok(false)
            }
            _ => Ok(false),
        }
    }

    pub fn drop_connection(&mut self) {
        if self.connected() {
            tracing::warn!(fusion_node = %self.addr, "fusion node connection dropped");
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
    use tokio::net::TcpListener;

    const TASK_ID: &str = "01J9A0TASK00000000000000001";

    fn node() -> Node {
        Node::from_config(&crate::config::test_config("node_id = \"ajar-node\"").unwrap())
    }

    /// The fusion node's side: read one framed message.
    async fn read_one(stream: &mut TcpStream) -> v2::SapientMessage {
        let payload = ajar_sapient_wire::read_frame(stream, &mut Vec::new())
            .await
            .expect("node closed before sending");
        ajar_sapient_wire::decode(&payload).unwrap()
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
            let task = v2::SapientMessage {
                timestamp: Some(ajar_sapient_wire::now()),
                node_id: Some("fusion".into()),
                destination_id: Some("ajar-node".into()),
                content: Some(Content::Task(v2::Task {
                    task_id: Some(TASK_ID.into()),
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
                    assert_eq!(a.task_id.as_deref(), Some(TASK_ID));
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
    async fn rejected_registration_reports_the_reasons() {
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
    async fn dropped_connection_re_registers_on_send() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let fusion = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let _ = read_one(&mut s).await;
            s.write_all(&ack(true, &[])).await.unwrap();
            drop(s);
            let (mut s, _) = listener.accept().await.unwrap();
            let reg = read_one(&mut s).await;
            assert!(
                matches!(reg.content, Some(Content::Registration(_))),
                "a reconnect registers first"
            );
            s.write_all(&ack(true, &[])).await.unwrap();
            let status = read_one(&mut s).await;
            assert!(matches!(status.content, Some(Content::StatusReport(_))));
        });
        let node = node();
        let mut link = FusionLink::new(&addr.to_string(), node.clone());
        link.ensure_registered().await.unwrap();
        assert!(link.next_inbound().await.is_err(), "the peer hung up");
        assert!(!link.connected());
        link.send(&node.status(true)).await.unwrap();
        assert_eq!(link.reconnects.load(Ordering::Relaxed), 1);
        fusion.await.unwrap();
    }

    #[tokio::test]
    async fn no_listener_is_an_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let mut link = FusionLink::new(&addr.to_string(), node());
        assert!(link.ensure_registered().await.is_err());
        assert_eq!(link.up.load(Ordering::Relaxed), 0);
    }
}
