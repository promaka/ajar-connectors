// SPDX-License-Identifier: Apache-2.0
//! TCP client transport — connect out to a feed and read framed messages. This is
//! how the stream feeds arrive: AIS aggregators and ship-network NMEA servers
//! expose a TCP port. If the feed drops, the source reconnects on the next read
//! rather than ending the loop.

use tokio::io::BufReader;
use tokio::net::TcpStream;

use crate::config::Framing;
use crate::runtime::FrameSource;
use crate::stream;

/// A reconnecting TCP client presented as a [`FrameSource`], framed per config.
pub struct TcpSource {
    remote: String,
    framing: Framing,
    reader: Option<BufReader<TcpStream>>,
}

impl TcpSource {
    async fn ensure_connected(&mut self) -> std::io::Result<()> {
        while self.reader.is_none() {
            match TcpStream::connect(&self.remote).await {
                Ok(stream) => {
                    let _ = stream.set_nodelay(true);
                    tracing::info!(remote = %self.remote, "feed connected");
                    self.reader = Some(BufReader::new(stream));
                }
                Err(e) => {
                    tracing::warn!(remote = %self.remote, error = %e, "feed connect failed, retrying");
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
            }
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl FrameSource for TcpSource {
    async fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            self.ensure_connected().await?;
            let reader = self.reader.as_mut().expect("connected above");
            let framed = match self.framing {
                Framing::Line => stream::read_line(reader, buf).await,
                Framing::LengthDelimited => stream::read_length_delimited(reader, buf).await,
            };
            match framed {
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

/// Build a TCP client source. The connection is opened lazily on the first read
/// (and re-opened after a drop), so startup never blocks on the feed.
pub fn open(connect: &str, framing: Framing) -> anyhow::Result<TcpSource> {
    Ok(TcpSource {
        remote: connect.to_string(),
        framing,
        reader: None,
    })
}
