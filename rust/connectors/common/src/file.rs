// SPDX-License-Identifier: Apache-2.0
//! File-tail transport — follow a file a source appends to (a log, a spooled
//! capture), yielding one line per frame. The ubiquitous "the system just writes
//! to a file" integration. Handles rotation/truncation by reopening from the
//! start, and waits for new appends rather than ending at EOF.

use std::time::Duration;

use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};

use crate::runtime::FrameSource;

/// Tails a file, one appended line per frame.
pub struct FileSource {
    path: String,
    reader: BufReader<File>,
    scratch: String,
    pos: u64,
}

#[async_trait::async_trait]
impl FrameSource for FileSource {
    async fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            self.scratch.clear();
            let n = self.reader.read_line(&mut self.scratch).await?;
            if n > 0 {
                self.pos += n as u64;
                let trimmed = self.scratch.trim_end_matches(['\r', '\n']);
                let bytes = trimmed.as_bytes();
                let m = bytes.len().min(buf.len());
                buf[..m].copy_from_slice(&bytes[..m]);
                return Ok(m);
            }
            // EOF: wait for appends. If the file shrank, it was rotated/truncated —
            // reopen from the start so we don't miss the new content.
            tokio::time::sleep(Duration::from_millis(500)).await;
            if let Ok(meta) = tokio::fs::metadata(&self.path).await {
                if meta.len() < self.pos {
                    tracing::info!(path = %self.path, "file rotated, reopening");
                    let file = File::open(&self.path).await?;
                    self.reader = BufReader::new(file);
                    self.pos = 0;
                }
            }
        }
    }

    fn describe(&self) -> String {
        format!("file {}", self.path)
    }
}

/// Open a file tail. With `from_start`, existing content is replayed before new
/// appends; otherwise following begins at the current end.
pub async fn open(path: &str, from_start: bool) -> anyhow::Result<FileSource> {
    let mut file = File::open(path)
        .await
        .map_err(|e| anyhow::anyhow!("opening {path}: {e}"))?;
    let mut pos = 0;
    if !from_start {
        pos = file.seek(std::io::SeekFrom::End(0)).await?;
    }
    Ok(FileSource {
        path: path.to_string(),
        reader: BufReader::new(file),
        scratch: String::new(),
        pos,
    })
}
