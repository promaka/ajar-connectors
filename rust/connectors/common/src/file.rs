// SPDX-License-Identifier: Apache-2.0
//! File transport — follow a file a source appends to (a log, a spooled
//! capture), one frame at a time, and keep following across rotation.
//!
//! Lines are the common case. A binary capture, such as a SAPIENT recording,
//! carries a length prefix instead; the reader then holds whatever bytes have
//! arrived until a whole frame is present, so a frame half-written by the
//! appender is never delivered as two.

use std::time::Duration;

use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncSeekExt, BufReader};

use crate::config::Framing;
use crate::runtime::FrameSource;

/// A frame can be at most the runtime's buffer; one prefix is held beyond it
/// only so an oversized length is reported rather than waited for.
const MAX_HELD: usize = crate::MAX_FRAME_BYTES + 4;

pub struct FileSource {
    path: String,
    reader: BufReader<File>,
    framing: Framing,
    scratch: String,
    /// Bytes read but not yet delivered, for length-prefixed framings.
    held: Vec<u8>,
    pos: u64,
}

impl FileSource {
    /// The length of the prefix and the payload length it declares, if `held`
    /// has a whole prefix.
    fn declared(&self) -> Option<(usize, usize)> {
        match self.framing {
            Framing::Line => None,
            Framing::LengthDelimited => (self.held.len() >= 2)
                .then(|| (2, u16::from_be_bytes([self.held[0], self.held[1]]) as usize)),
            Framing::LengthU32le => (self.held.len() >= 4).then(|| {
                let n =
                    u32::from_le_bytes([self.held[0], self.held[1], self.held[2], self.held[3]]);
                (4, n as usize)
            }),
        }
    }

    /// Deliver the next whole frame from `held`, if one is complete.
    fn take_frame(&mut self, buf: &mut [u8]) -> std::io::Result<Option<usize>> {
        let Some((prefix, n)) = self.declared() else {
            return Ok(None);
        };
        if n > buf.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("length-prefixed frame {n} exceeds buffer {}", buf.len()),
            ));
        }
        if self.held.len() < prefix + n {
            return Ok(None);
        }
        buf[..n].copy_from_slice(&self.held[prefix..prefix + n]);
        self.held.drain(..prefix + n);
        Ok(Some(n))
    }

    async fn reopen_if_rotated(&mut self) -> std::io::Result<()> {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if let Ok(meta) = tokio::fs::metadata(&self.path).await {
            if meta.len() < self.pos {
                tracing::info!(path = %self.path, "file rotated, reopening");
                let file = File::open(&self.path).await?;
                self.reader = BufReader::new(file);
                self.held.clear();
                self.pos = 0;
            }
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl FrameSource for FileSource {
    async fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self.framing == Framing::Line {
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
            } else {
                if let Some(n) = self.take_frame(buf)? {
                    return Ok(n);
                }
                // Read what has arrived so far; a frame still being appended
                // stays held until the rest lands.
                let mut chunk = [0u8; 8192];
                let n = self.reader.read(&mut chunk).await?;
                if n > 0 {
                    self.pos += n as u64;
                    if self.held.len() + n > MAX_HELD {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "no frame boundary within the frame-size bound; the file is not in the configured framing",
                        ));
                    }
                    self.held.extend_from_slice(&chunk[..n]);
                    continue;
                }
            }
            self.reopen_if_rotated().await?;
        }
    }

    fn describe(&self) -> String {
        format!("file {}", self.path)
    }
}

pub async fn open(path: &str, from_start: bool, framing: Framing) -> anyhow::Result<FileSource> {
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
        framing,
        scratch: String::new(),
        held: Vec::new(),
        pos,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("ajar-file-{}-{}", std::process::id(), name));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("feed.bin")
    }

    #[tokio::test]
    async fn length_prefixed_frames_are_delivered_whole_and_in_order() {
        let path = tmp("u32le");
        let mut bytes = Vec::new();
        for payload in [&b"first"[..], &b"second one"[..], &[0u8, 1, 2][..]] {
            bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            bytes.extend_from_slice(payload);
        }
        std::fs::write(&path, &bytes).unwrap();
        let mut src = open(path.to_str().unwrap(), true, Framing::LengthU32le)
            .await
            .unwrap();
        let mut buf = vec![0u8; 64];
        let n = src.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"first");
        let n = src.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"second one");
        let n = src.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &[0, 1, 2]);
    }

    #[tokio::test]
    async fn a_frame_still_being_written_waits_for_its_rest() {
        let path = tmp("partial");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&7u32.to_le_bytes());
        bytes.extend_from_slice(b"abc");
        std::fs::write(&path, &bytes).unwrap();
        let mut src = open(path.to_str().unwrap(), true, Framing::LengthU32le)
            .await
            .unwrap();
        let mut buf = vec![0u8; 64];
        let p = path.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(700)).await;
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new().append(true).open(p).unwrap();
            f.write_all(b"defg").unwrap();
        });
        let n = src.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"abcdefg");
    }

    #[tokio::test]
    async fn an_oversized_prefix_is_an_error_not_a_wait() {
        let path = tmp("oversized");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(u32::MAX).to_le_bytes());
        std::fs::write(&path, &bytes).unwrap();
        let mut src = open(path.to_str().unwrap(), true, Framing::LengthU32le)
            .await
            .unwrap();
        let mut buf = vec![0u8; 64];
        let err = src.recv(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }
}
