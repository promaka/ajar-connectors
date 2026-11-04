// SPDX-License-Identifier: Apache-2.0
//! File transport: follow a file a source appends to, across rotation. With a
//! length-prefixed framing, bytes are held until a whole frame has arrived, so
//! a frame half-written by the appender is never delivered as two.

use std::time::Duration;

use anyhow::Context;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncSeekExt, BufReader};

use crate::config::Framing;
use crate::runtime::FrameSource;

/// The runtime's buffer plus one prefix, so an oversized length is reported
/// rather than waited for.
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
    /// The prefix length and the payload length it declares, once `held` has a
    /// whole prefix.
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
        .with_context(|| format!("opening {path}"))?;
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
    use std::io::Write;

    /// A capture of u32le-prefixed `frames`, then `tail` raw bytes.
    fn capture(frames: &[&[u8]], tail: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        for payload in frames {
            f.write_all(&(payload.len() as u32).to_le_bytes()).unwrap();
            f.write_all(payload).unwrap();
        }
        f.write_all(tail).unwrap();
        f
    }

    async fn open_u32le(f: &tempfile::NamedTempFile) -> FileSource {
        open(f.path().to_str().unwrap(), true, Framing::LengthU32le)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn length_prefixed_frames_arrive_whole_in_order() {
        let f = capture(&[b"first", b"second one", &[0, 1, 2]], &[]);
        let mut src = open_u32le(&f).await;
        let mut buf = vec![0u8; 64];
        let n = src.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"first");
        let n = src.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"second one");
        let n = src.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &[0, 1, 2]);
    }

    #[tokio::test]
    async fn partial_frame_waits_for_its_rest() {
        let mut tail = 7u32.to_le_bytes().to_vec();
        tail.extend_from_slice(b"abc");
        let f = capture(&[], &tail);
        let mut src = open_u32le(&f).await;
        let mut buf = vec![0u8; 64];
        let p = f.path().to_path_buf();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(700)).await;
            let mut f = std::fs::OpenOptions::new().append(true).open(p).unwrap();
            f.write_all(b"defg").unwrap();
        });
        let n = src.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"abcdefg");
    }

    #[tokio::test]
    async fn oversized_prefix_is_an_error_not_a_wait() {
        let f = capture(&[], &u32::MAX.to_le_bytes());
        let mut src = open_u32le(&f).await;
        let mut buf = vec![0u8; 64];
        let err = src.recv(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }
}
