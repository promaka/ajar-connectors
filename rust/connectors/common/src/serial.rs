// SPDX-License-Identifier: Apache-2.0
//! Serial-line transport (RS-232/422/485), one line per frame. A read error
//! drops the handle and reopens the device with backoff, so a reseated cable
//! or a re-enumerated USB adapter recovers.

use std::time::Duration;

use tokio::io::BufReader;
use tokio_serial::{SerialPortBuilderExt, SerialStream};

use crate::runtime::FrameSource;
use crate::stream;

pub struct SerialSource {
    device: String,
    baud: u32,
    reader: Option<BufReader<SerialStream>>,
}

/// Open `device`, retrying until it appears.
async fn open_port(device: &str, baud: u32) -> BufReader<SerialStream> {
    loop {
        match tokio_serial::new(device, baud).open_native_async() {
            Ok(port) => {
                tracing::info!(device = %device, baud, "serial port open");
                return BufReader::new(port);
            }
            Err(e) => {
                tracing::warn!(device = %device, error = %e, "serial open failed, retrying");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
}

#[async_trait::async_trait]
impl FrameSource for SerialSource {
    async fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let reader = match &mut self.reader {
                Some(reader) => reader,
                None => self.reader.insert(open_port(&self.device, self.baud).await),
            };
            match stream::read_line(reader, buf).await {
                Ok(n) => return Ok(n),
                // An overlong line (e.g. a baud mismatch) is bad input, not a
                // dead port.
                Err(e) if e.kind() == std::io::ErrorKind::InvalidData => return Err(e),
                Err(e) => {
                    tracing::warn!(device = %self.device, error = %e, "serial read error, reopening");
                    self.reader = None;
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }

    fn describe(&self) -> String {
        format!("serial {}@{}", self.device, self.baud)
    }
}

/// Build a serial source. The device opens on the first read, so startup
/// never blocks on absent hardware.
pub fn open(device: &str, baud: u32) -> anyhow::Result<SerialSource> {
    Ok(SerialSource {
        device: device.to_string(),
        baud,
        reader: None,
    })
}
