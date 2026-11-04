// SPDX-License-Identifier: Apache-2.0
//! TCP server transport: accept sources that push their feed to a local port.
//! Each connection is framed on its own and their frames interleave. A bounded
//! channel backpressures a flooding pusher.

use anyhow::Context;
use tokio::io::BufReader;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use crate::config::Framing;
use crate::runtime::FrameSource;
use crate::stream;

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
            // The accept loop holds a sender for the source's lifetime.
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

/// Bind now, so a bad `bind` fails at startup, and accept in the background.
pub async fn open(bind: &str, framing: Framing) -> anyhow::Result<TcpServerSource> {
    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("binding tcp-server {bind}"))?;
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
    let mut buf = vec![0u8; crate::MAX_FRAME_BYTES];
    loop {
        let framed = stream::read_frame(&mut reader, framing, &mut buf).await;
        match framed {
            Ok(n) => {
                // The source is gone: the connector is shutting down.
                if tx.send(buf[..n].to_vec()).await.is_err() {
                    return;
                }
            }
            // A long line was drained, so the stream is in sync; an oversize
            // length prefix left its payload unread, so the next read is not.
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

    /// The bound address, read back from the description.
    fn addr(src: &TcpServerSource) -> String {
        src.describe()
            .strip_prefix("tcp-server ")
            .unwrap()
            .split(' ')
            .next()
            .unwrap()
            .to_string()
    }

    #[tokio::test]
    async fn receives_lines_from_concurrent_pushers() {
        let mut src = open("127.0.0.1:0", Framing::Line).await.unwrap();
        let addr = addr(&src);

        let mut pusher = TcpStream::connect(&addr).await.unwrap();
        pusher.write_all(b"first\r\nsecond\n").await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = src.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"first");
        let n = src.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"second");

        let mut pusher2 = TcpStream::connect(&addr).await.unwrap();
        pusher2.write_all(b"third\n").await.unwrap();
        let n = src.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"third");
    }

    #[tokio::test]
    async fn survives_a_pusher_disconnecting() {
        let mut src = open("127.0.0.1:0", Framing::Line).await.unwrap();
        let addr = addr(&src);

        {
            let mut pusher = TcpStream::connect(&addr).await.unwrap();
            pusher.write_all(b"before-drop\n").await.unwrap();
            pusher.shutdown().await.unwrap();
        }

        let mut buf = vec![0u8; 1024];
        let n = src.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"before-drop");

        let mut pusher = TcpStream::connect(&addr).await.unwrap();
        pusher.write_all(b"after-reconnect\n").await.unwrap();
        let n = src.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"after-reconnect");
    }
}
