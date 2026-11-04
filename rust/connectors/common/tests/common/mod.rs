// SPDX-License-Identifier: Apache-2.0
//! Shared scaffolding for the nats-server gates.

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ajar_connector::{Event, EventBuilder};
use ajar_connector_common::{Config, FrameParser, FrameSource, ParseError};
use tokio::sync::mpsc;

pub const SEED: [u8; 32] = [0x42; 32];

/// The `nats-server` binary (`NATS_SERVER_BIN` or on `PATH`). Missing, a gate
/// fails in CI and skips locally.
pub fn nats_server(gate: &str) -> Option<String> {
    let candidate = std::env::var("NATS_SERVER_BIN").unwrap_or_else(|_| "nats-server".to_string());
    let found = Command::new(&candidate)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if found {
        Some(candidate)
    } else if std::env::var("CI").is_ok() {
        panic!("nats-server is required in CI: the {gate} gate must run, not skip");
    } else {
        eprintln!("{gate} gate SKIPPED: no nats-server binary (brew install nats-server)");
        None
    }
}

/// A broker child process, killed on drop so a panicking test cannot leak it.
pub struct Broker(Child);

impl Broker {
    /// Start a broker on `port`, with JetStream stored in `jetstream` if given.
    pub fn start(bin: &str, port: u16, jetstream: Option<&Path>) -> Broker {
        let mut cmd = Command::new(bin);
        cmd.args(["-p", &port.to_string()]);
        if let Some(store) = jetstream {
            cmd.args(["-js", "-sd", store.to_str().unwrap()]);
        }
        let child = cmd
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawning nats-server");
        Broker(child)
    }
}

impl Drop for Broker {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub async fn wait_until_up(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return;
        }
        assert!(Instant::now() < deadline, "nats-server did not come up");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

pub fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

/// Write the [`SEED`] key and a config for `source` to `dir`, with `extra`
/// appended, and load it.
pub fn config(dir: &Path, source: &str, nats_url: &str, extra: &str) -> Config {
    let seed_path = dir.join("gate.seed");
    std::fs::write(&seed_path, SEED).unwrap();
    let config_path = dir.join("gate.toml");
    std::fs::write(
        &config_path,
        format!(
            "source_id = \"{source}\"\n\
             nats_url = \"{nats_url}\"\n\
             signing_key_path = \"{}\"\n\
             [transport]\n\
             kind = \"udp\"\n\
             bind = \"127.0.0.1:0\"\n\
             {extra}",
            seed_path.display()
        ),
    )
    .unwrap();
    Config::load(config_path.to_str().unwrap()).unwrap()
}

/// Frames from the test, through a channel. A closed channel blocks forever;
/// the test aborts the task.
pub struct ChannelSource(pub mpsc::UnboundedReceiver<Vec<u8>>);

#[async_trait::async_trait]
impl FrameSource for ChannelSource {
    async fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.0.recv().await {
            Some(frame) => {
                buf[..frame.len()].copy_from_slice(&frame);
                Ok(frame.len())
            }
            None => std::future::pending().await,
        }
    }
    fn describe(&self) -> String {
        "test channel".into()
    }
}

/// Each event's (id, canonical bytes), as built.
pub type Built = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

/// One `mim:vessel` event per frame, recorded in `built`.
pub struct RecordingParser {
    pub source: &'static str,
    pub built: Built,
}

impl FrameParser for RecordingParser {
    fn parse(&self, frame: &[u8]) -> Result<Vec<Event>, ParseError> {
        let event = EventBuilder::new(self.source, "mim:vessel")
            .new_id()
            .now()
            .attribute("track_number", String::from_utf8_lossy(frame))
            .build()?;
        self.built
            .lock()
            .expect("no poisoned lock")
            .push((event.id.clone(), ajar_connector::canonical_bytes(&event)));
        Ok(vec![event])
    }
}
