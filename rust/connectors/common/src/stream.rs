// SPDX-License-Identifier: Apache-2.0
//! Shared framing for byte-stream transports (TCP, serial, exec, stdin).
//!
//! A datagram transport (UDP) delivers one frame per packet, but a *stream*
//! delivers an undelimited flow of bytes. [`Framing`] says how to cut it into
//! frames — newline-delimited text or a length-prefixed binary record — and
//! [`StreamSource`] applies it over any async reader, so every stream transport
//! shares exactly one framing implementation.
//!
//! Both framings are **bounded by the caller's buffer**: a stream that never
//! sends a newline (or claims an enormous length) cannot grow memory without
//! limit — the over-long frame is drained and rejected, and the stream resyncs.

use std::io::{Error, ErrorKind, Result};

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, BufReader};

use crate::config::Framing;
use crate::runtime::FrameSource;

/// Read one newline-delimited frame (without its terminator) into `buf`, bounded
/// by `buf.len()`. A line longer than the buffer is drained up to its newline and
/// rejected with `InvalidData`, so a newline-less flood cannot exhaust memory and
/// the stream resynchronises at the next line.
pub(crate) async fn read_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    buf: &mut [u8],
) -> Result<usize> {
    let mut len = 0usize;
    let mut overflow = false;
    let saw_newline;
    loop {
        // Copy out of the borrowed chunk, then release the borrow before consuming.
        let (consumed, done, eof) = {
            let chunk = reader.fill_buf().await?;
            if chunk.is_empty() {
                (0, false, true)
            } else if let Some(pos) = chunk.iter().position(|&b| b == b'\n') {
                copy_bounded(buf, &mut len, &mut overflow, &chunk[..pos]);
                (pos + 1, true, false)
            } else {
                let n = chunk.len();
                copy_bounded(buf, &mut len, &mut overflow, chunk);
                (n, false, false)
            }
        };
        reader.consume(consumed);
        if eof {
            if len == 0 && !overflow {
                return Err(Error::new(ErrorKind::UnexpectedEof, "stream closed"));
            }
            saw_newline = false;
            break;
        }
        if done {
            saw_newline = true;
            break;
        }
    }
    if overflow {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "line exceeds frame buffer; dropped and resynchronised",
        ));
    }
    let _ = saw_newline;
    // Trim a trailing CR (CRLF line endings).
    while len > 0 && buf[len - 1] == b'\r' {
        len -= 1;
    }
    Ok(len)
}

/// Copy `src` into `buf[len..]`, advancing `len`. If it would overflow the buffer,
/// copy what fits and set `overflow` — the caller keeps draining to the newline.
fn copy_bounded(buf: &mut [u8], len: &mut usize, overflow: &mut bool, src: &[u8]) {
    let room = buf.len().saturating_sub(*len);
    if src.len() > room {
        buf[*len..].copy_from_slice(&src[..room]);
        *len = buf.len();
        *overflow = true;
    } else {
        buf[*len..*len + src.len()].copy_from_slice(src);
        *len += src.len();
    }
}

/// Read one length-delimited frame: a 2-byte big-endian length prefix, then that
/// many payload bytes into `buf`. A length larger than the buffer is rejected.
pub(crate) async fn read_length_delimited<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut [u8],
) -> Result<usize> {
    let mut len = [0u8; 2];
    reader.read_exact(&mut len).await?;
    let n = u16::from_be_bytes(len) as usize;
    if n > buf.len() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("length-delimited frame {n} exceeds buffer {}", buf.len()),
        ));
    }
    reader.read_exact(&mut buf[..n]).await?;
    Ok(n)
}

/// A [`FrameSource`] over any async byte stream, applying a [`Framing`].
pub(crate) struct StreamSource<R> {
    reader: BufReader<R>,
    framing: Framing,
    describe: String,
}

impl<R: AsyncRead + Unpin + Send> StreamSource<R> {
    pub(crate) fn new(inner: R, framing: Framing, describe: String) -> Self {
        Self {
            reader: BufReader::new(inner),
            framing,
            describe,
        }
    }
}

#[async_trait::async_trait]
impl<R: AsyncRead + Unpin + Send> FrameSource for StreamSource<R> {
    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self.framing {
            Framing::Line => read_line(&mut self.reader, buf).await,
            Framing::LengthDelimited => read_length_delimited(&mut self.reader, buf).await,
        }
    }

    fn describe(&self) -> String {
        self.describe.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::io::Cursor;

    async fn lines(input: &[u8], cap: usize) -> Vec<std::io::Result<Vec<u8>>> {
        let mut reader = BufReader::new(Cursor::new(input.to_vec()));
        let mut out = Vec::new();
        let mut buf = vec![0u8; cap];
        loop {
            match read_line(&mut reader, &mut buf).await {
                Ok(n) => out.push(Ok(buf[..n].to_vec())),
                Err(e) if e.kind() == ErrorKind::UnexpectedEof => break,
                Err(e) => out.push(Err(e)),
            }
        }
        out
    }

    #[tokio::test]
    async fn splits_lines_and_trims_crlf() {
        let got = lines(b"one\r\ntwo\nthree", 64).await;
        let ok: Vec<_> = got.into_iter().map(|r| r.unwrap()).collect();
        assert_eq!(
            ok,
            vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec()]
        );
    }

    #[tokio::test]
    async fn overlong_line_is_rejected_then_stream_resyncs() {
        // A 100-byte line with an 8-byte buffer: rejected, then the next line
        // (within the cap) is delivered.
        let mut input = vec![b'x'; 100];
        input.push(b'\n');
        input.extend_from_slice(b"ok\n");
        let got = lines(&input, 8).await;
        assert!(got[0].is_err()); // overlong, dropped
        assert_eq!(got[1].as_ref().unwrap(), b"ok"); // resynced
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2048))]

        /// The line reader must never panic and never exceed the buffer, whatever
        /// the byte stream and buffer size.
        #[test]
        fn read_line_never_panics_or_overflows(
            data in proptest::collection::vec(any::<u8>(), 0..4096),
            cap in 1usize..256,
        ) {
            let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
            rt.block_on(async {
                let results = lines(&data, cap).await;
                for line in results.into_iter().flatten() {
                    prop_assert!(line.len() <= cap);
                }
                Ok(())
            })?;
        }
    }
}
