// SPDX-License-Identifier: Apache-2.0
//! Exec transport — run a command and read its stdout, one line per frame. This
//! wraps *any* CLI tool or vendor SDK binary that prints records
//! (`some-vendor-cli --stream`), turning it into an Ajar source with no code. If
//! the command exits, it is respawned.

use std::process::Stdio;
use std::time::Duration;

use tokio::io::BufReader;
use tokio::process::{ChildStdout, Command};

use crate::runtime::FrameSource;
use crate::stream;

/// Runs a command and yields its stdout lines, respawning on exit.
pub struct ExecSource {
    command: String,
    args: Vec<String>,
    reader: Option<BufReader<ChildStdout>>,
}

impl ExecSource {
    fn spawn(&mut self) -> std::io::Result<()> {
        let mut child = Command::new(&self.command)
            .args(&self.args)
            .stdout(Stdio::piped())
            .stdin(Stdio::null())
            .spawn()?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| std::io::Error::other("child produced no stdout"))?;
        // Detach: the OS reaps it; we only care about the byte stream. A fresh
        // spawn replaces it if it exits.
        tokio::spawn(async move {
            let _ = child.wait().await;
        });
        self.reader = Some(BufReader::new(stdout));
        Ok(())
    }
}

#[async_trait::async_trait]
impl FrameSource for ExecSource {
    async fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self.reader.is_none() {
                if let Err(e) = self.spawn() {
                    tracing::warn!(command = %self.command, error = %e, "spawn failed, retrying");
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }
                tracing::info!(command = %self.command, "command started");
            }
            let reader = self.reader.as_mut().expect("spawned above");
            match stream::read_line(reader, buf).await {
                Ok(n) => return Ok(n),
                Err(e) => {
                    tracing::warn!(command = %self.command, error = %e, "command output ended, respawning");
                    self.reader = None;
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }

    fn describe(&self) -> String {
        format!("exec {} {}", self.command, self.args.join(" "))
    }
}

/// Build an exec source. The command is spawned lazily on the first read.
pub fn open(command: &str, args: &[String]) -> anyhow::Result<ExecSource> {
    Ok(ExecSource {
        command: command.to_string(),
        args: args.to_vec(),
        reader: None,
    })
}
