// SPDX-License-Identifier: Apache-2.0
//! Exec transport: run a command and read its stdout, one line per frame,
//! respawning it when it exits.

use std::process::Stdio;
use std::time::Duration;

use tokio::io::BufReader;
use tokio::process::{ChildStdout, Command};

use crate::runtime::FrameSource;
use crate::stream;

pub struct ExecSource {
    command: String,
    args: Vec<String>,
    reader: Option<BufReader<ChildStdout>>,
}

fn spawn(command: &str, args: &[String]) -> std::io::Result<BufReader<ChildStdout>> {
    let mut child = Command::new(command)
        .args(args)
        .stdout(Stdio::piped())
        .stdin(Stdio::null())
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other("child produced no stdout"))?;
    // Reap the child in the background; only its stdout matters here.
    tokio::spawn(async move {
        let _ = child.wait().await;
    });
    Ok(BufReader::new(stdout))
}

#[async_trait::async_trait]
impl FrameSource for ExecSource {
    async fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let reader = match &mut self.reader {
                Some(reader) => reader,
                None => match spawn(&self.command, &self.args) {
                    Ok(reader) => {
                        tracing::info!(command = %self.command, "command started");
                        self.reader.insert(reader)
                    }
                    Err(e) => {
                        tracing::warn!(command = %self.command, error = %e, "spawn failed, retrying");
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        continue;
                    }
                },
            };
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

/// Build an exec source. The command is spawned on the first read.
pub fn open(command: &str, args: &[String]) -> anyhow::Result<ExecSource> {
    Ok(ExecSource {
        command: command.to_string(),
        args: args.to_vec(),
        reader: None,
    })
}
