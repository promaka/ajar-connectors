// SPDX-License-Identifier: Apache-2.0
//! Stdin transport — read this process's standard input, one line per frame. Pipe
//! from anything: `producer | ajar-<connector>`. The simplest possible glue for a
//! source that can already print to a pipe.

use crate::config::Framing;
use crate::runtime::FrameSource;
use crate::stream::StreamSource;

/// Build a stdin source (line-framed).
pub fn open() -> anyhow::Result<impl FrameSource> {
    Ok(StreamSource::new(
        tokio::io::stdin(),
        Framing::Line,
        "stdin".to_string(),
    ))
}
