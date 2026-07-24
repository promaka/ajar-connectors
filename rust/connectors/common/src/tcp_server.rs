// SPDX-License-Identifier: Apache-2.0
//! TCP server transport — listen on a local address and accept connections from
//! sources that *push* their feed to a configured endpoint ("point your output at
//! 10.0.0.5:9000"), the common legacy pattern that is the mirror image of
//! `tcp-client`. Multiple pushers may connect at once; each connection is framed
//! independently and their frames interleave. A dropped pusher simply reconnects.
//!
//! Frames flow through a bounded channel, so a flooding pusher is backpressured
//! rather than growing memory; an over-long line on one connection is dropped
//! and that connection resynchronises, exactly like the other stream transports.

use tokio::io::BufReader;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use crate::config::Framing;
use crate::runtime::FrameSource;
use crate::stream;

/// Matches the runtime's receive buffer: one frame can never exceed it.
const MAX_FRAME: usize = 64 * 1024;
/// Frames buffered across all connections before pushers are backpressured.
const CHANNEL_FRAMES: usize = 256;

/// Frames pushed by connected sources, in arrival order.
pub struct TcpServerSource {
    rx: mpsc::Receiver<Vec<u8>>,
    describe: String,
}

#[async_trait::async_trait]
impl FrameSource for TcpServerSource {
    async fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.rx.recv().await {
            Some(frame) => {
                let n = frame.len().min(buf.len());
                buf[..n].copy_from_slice(&frame[..n]);
                Ok(n)
            }
            // The accept loop holds a sender for the lifetime of the source, so
            // this only happens if it died — surface it rather than spin.
            None => Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "tcp-server accept loop ended",
            )),
        }
    }

    fn describe(&self) -> String {
        self.describe.clone()
    }
}

/// Bind and start accepting pushers. Binding is eager (a bad `bind` fails fast at
/// startup); connections are handled in the background.
pub async fn open(bind: &str, framing: Framing) -> anyhow::Result<TcpServerSource> {
    let listener = TcpListener::bind(bind)
        .await
        .map_err(|e| anyhow::anyhow!("binding tcp-server {bind}: {e}"))?;
    let local = listener.local_addr()?;
    let (tx, rx) = mpsc::channel(CHANNEL_FRAMES);
    tokio::spawn(accept_loop(listener, framing, tx));
    Ok(TcpServerSource {
        rx,
        describe: format!("tcp-server {local} ({framing:?})"),
    })
}

async fn accept_loop(listener: TcpListener, framing: Framing, tx: mpsc::Sender<Vec<u8>>) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                tracing::info!(peer = %peer, "source connected");
                let _ = stream.set_nodelay(true);
                tokio::spawn(connection_loop(stream, framing, tx.clone()));
            }
            Err(e) => {
                tracing::warn!(error = %e, "accept failed, retrying");
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
    }
}

async fn connection_loop(stream: TcpStream, framing: Framing, tx: mpsc::Sender<Vec<u8>>) {
    let peer = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".into());
    let mut reader = BufReader::new(stream);
    let mut buf = vec![0u8; MAX_FRAME];
    loop {
        let framed = match framing {
            Framing::Line => stream::read_line(&mut reader, &mut buf).await,
            Framing::LengthDelimited => stream::read_length_delimited(&mut reader, &mut buf).await,
        };
        match framed {
            Ok(n) => {
                // Backpressure: a full channel slows the pusher, never grows memory.
                if tx.send(buf[..n].to_vec()).await.is_err() {
                    return; // source dropped; connector shutting down
                }
            }
            // Over-long frame: drop it, keep the connection (it resynchronised).
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                tracing::warn!(peer = %peer, error = %e, "dropping oversized frame");
            }
            Err(_) => {
                tracing::info!(peer = %peer, "source disconnected");
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn receives_pushed_lines_from_a_connecting_source() {
        let mut src = open("127.0.0.1:0", Framing::Line).await.unwrap();
        let addr = src.describe();
        let addr = addr
            .strip_prefix("tcp-server ")
            .unwrap()
            .split(' ')
            .next()
            .unwrap()
            .to_string();

        let mut pusher = TcpStream::connect(&addr).await.unwrap();
        pusher.write_all(b"first\r\nsecond\n").await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = src.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"first");
        let n = src.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"second");

        // A second pusher's frames interleave on the same source.
        let mut pusher2 = TcpStream::connect(&addr).await.unwrap();
        pusher2.write_all(b"third\n").await.unwrap();
        let n = src.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"third");
    }

    #[tokio::test]
    async fn source_survives_a_pusher_disconnecting() {
        let mut src = open("127.0.0.1:0", Framing::Line).await.unwrap();
        let addr = src.describe();
        let addr = addr
            .strip_prefix("tcp-server ")
            .unwrap()
            .split(' ')
            .next()
            .unwrap()
            .to_string();

        {
            let mut pusher = TcpStream::connect(&addr).await.unwrap();
            pusher.write_all(b"before-drop\n").await.unwrap();
            pusher.shutdown().await.unwrap();
        } // pusher gone

        let mut buf = vec![0u8; 1024];
        let n = src.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"before-drop");

        // A fresh pusher connects and is heard — no restart needed.
        let mut pusher = TcpStream::connect(&addr).await.unwrap();
        pusher.write_all(b"after-reconnect\n").await.unwrap();
        let n = src.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"after-reconnect");
    }
}
