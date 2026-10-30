// SPDX-License-Identifier: Apache-2.0
//! Framing for byte-stream transports, bounded by the caller's buffer. A longer
//! line is drained and rejected, and the stream resyncs at the next newline. An
//! oversize length prefix is rejected before its payload is read, so the next
//! read takes payload bytes as a prefix.

use std::io::{Error, ErrorKind, Result};

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, BufReader};

use crate::config::Framing;
use crate::runtime::FrameSource;

/// Read one newline-delimited frame, without its terminator or trailing CRs,
/// into `buf`. A longer line is drained to its newline and rejected with
/// `InvalidData`.
pub(crate) async fn read_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    buf: &mut [u8],
) -> Result<usize> {
    let mut len = 0usize;
    let mut overflow = false;
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
            break;
        }
        if done {
            break;
        }
    }
    if overflow {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "line exceeds frame buffer; dropped and resynchronised",
        ));
    }
    while len > 0 && buf[len - 1] == b'\r' {
        len -= 1;
    }
    Ok(len)
}

/// Copy `src` into `buf[len..]`, advancing `len`. What does not fit is dropped
/// and `overflow` set.
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

/// Read `n` payload bytes into `buf`, refusing before any read when `n` does
/// not fit.
async fn read_payload<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut [u8],
    n: usize,
    framing: &str,
) -> Result<usize> {
    if n > buf.len() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("{framing} frame {n} exceeds buffer {}", buf.len()),
        ));
    }
    reader.read_exact(&mut buf[..n]).await?;
    Ok(n)
}

/// Read one frame as `framing` says, for `tcp-client`, `tcp-server` and `stdin`.
pub(crate) async fn read_frame<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    framing: Framing,
    buf: &mut [u8],
) -> Result<usize> {
    match framing {
        Framing::Line => read_line(reader, buf).await,
        Framing::LengthDelimited => {
            let mut len = [0u8; 2];
            reader.read_exact(&mut len).await?;
            let n = u16::from_be_bytes(len) as usize;
            read_payload(reader, buf, n, "length-delimited").await
        }
        Framing::LengthU32le => {
            let mut len = [0u8; 4];
            reader.read_exact(&mut len).await?;
            let n = u32::from_le_bytes(len) as usize;
            read_payload(reader, buf, n, "length-u32le").await
        }
    }
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
        read_frame(&mut self.reader, self.framing, buf).await
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
        let mut input = vec![b'x'; 100];
        input.push(b'\n');
        input.extend_from_slice(b"ok\n");
        let got = lines(&input, 8).await;
        assert!(got[0].is_err(), "a line longer than the buffer is rejected");
        assert_eq!(
            got[1].as_ref().unwrap(),
            b"ok",
            "the next line is delivered"
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2048))]

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
