// SPDX-License-Identifier: Apache-2.0
//! TCP client transport: connect out to a feed and read framed messages,
//! reconnecting on the next read if the feed drops.

use std::time::Duration;

use tokio::io::BufReader;
use tokio::net::TcpStream;

use crate::config::Framing;
use crate::runtime::FrameSource;
use crate::stream;

pub struct TcpSource {
    remote: String,
    framing: Framing,
    reader: Option<BufReader<TcpStream>>,
}

/// Connect to `remote`, retrying until it answers.
async fn connect(remote: &str) -> BufReader<TcpStream> {
    loop {
        match TcpStream::connect(remote).await {
            Ok(stream) => {
                let _ = stream.set_nodelay(true);
                tracing::info!(remote = %remote, "feed connected");
                return BufReader::new(stream);
            }
            Err(e) => {
                tracing::warn!(remote = %remote, error = %e, "feed connect failed, retrying");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
}

#[async_trait::async_trait]
impl FrameSource for TcpSource {
    async fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let reader = match &mut self.reader {
                Some(reader) => reader,
                None => self.reader.insert(connect(&self.remote).await),
            };
            match stream::read_frame(reader, self.framing, buf).await {
                Ok(n) => return Ok(n),
                Err(e) => {
                    tracing::warn!(remote = %self.remote, error = %e, "feed read error, reconnecting");
                    self.reader = None;
                }
            }
        }
    }

    fn describe(&self) -> String {
        format!("tcp-client {} ({:?})", self.remote, self.framing)
    }
}

/// Build a TCP client source. It connects on the first read, so startup never
/// blocks on the feed.
pub fn open(connect: &str, framing: Framing) -> anyhow::Result<TcpSource> {
    Ok(TcpSource {
        remote: connect.to_string(),
        framing,
        reader: None,
    })
}
