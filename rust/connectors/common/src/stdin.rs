// SPDX-License-Identifier: Apache-2.0
//! Stdin transport: read this process's standard input, framed per config.

use crate::config::Framing;
use crate::runtime::FrameSource;
use crate::stream::StreamSource;

pub fn open(framing: Framing) -> anyhow::Result<impl FrameSource> {
    Ok(StreamSource::new(
        tokio::io::stdin(),
        framing,
        "stdin".to_string(),
    ))
}
