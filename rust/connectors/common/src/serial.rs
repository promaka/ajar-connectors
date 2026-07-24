// SPDX-License-Identifier: Apache-2.0
//! Serial-line transport (RS-232/422/485) — many sensors emit NMEA or vendor
//! ASCII over a serial port. One line per frame. Requires the `serial` feature.
//!
//! Field serial links blip: a cable is reseated, a USB adapter re-enumerates, a
//! sensor power-cycles. A read error therefore drops the handle and re-opens the
//! device with backoff — the same discipline as the TCP transport — instead of
//! retrying a dead file descriptor forever.

use tokio::io::BufReader;
use tokio_serial::{SerialPortBuilderExt, SerialStream};

use crate::runtime::FrameSource;
use crate::stream;

/// A reconnecting serial port presented as a line-framed [`FrameSource`].
pub struct SerialSource {
    device: String,
    baud: u32,
    reader: Option<BufReader<SerialStream>>,
}

impl SerialSource {
    async fn ensure_open(&mut self) {
        while self.reader.is_none() {
            match tokio_serial::new(&self.device, self.baud).open_native_async() {
                Ok(port) => {
                    tracing::info!(device = %self.device, baud = self.baud, "serial port open");
                    self.reader = Some(BufReader::new(port));
                }
                Err(e) => {
                    tracing::warn!(device = %self.device, error = %e, "serial open failed, retrying");
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
            }
        }
    }
}

#[async_trait::async_trait]
impl FrameSource for SerialSource {
    async fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            self.ensure_open().await;
            let reader = self.reader.as_mut().expect("opened above");
            match stream::read_line(reader, buf).await {
                Ok(n) => return Ok(n),
                // An overlong line is bad input (e.g. baud mismatch), not a dead
                // port — surface it without thrashing the device.
                Err(e) if e.kind() == std::io::ErrorKind::InvalidData => return Err(e),
                Err(e) => {
                    tracing::warn!(device = %self.device, error = %e, "serial read error, reopening");
                    self.reader = None;
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }
    }

    fn describe(&self) -> String {
        format!("serial {}@{}", self.device, self.baud)
    }
}

/// Build a serial source. The device is opened lazily on the first read (and
/// re-opened after an error), so startup never blocks on absent hardware.
pub fn open(device: &str, baud: u32) -> anyhow::Result<SerialSource> {
    Ok(SerialSource {
        device: device.to_string(),
        baud,
        reader: None,
    })
}
