// SPDX-License-Identifier: Apache-2.0
//! `ajar-sink`: subscribe to sealed events, verify each against its publisher's
//! registered key, append it to a hash-chained SQLite database, and re-verify
//! the whole chain on demand. A development and evaluation sink, not Ajar Core:
//! no policy, ontology or classification handling.

mod cot_out;
mod store;

use std::collections::HashMap;
use std::io::Read;
use std::path::Path;
use std::process::ExitCode;

use ajar_connector::{SigningKey, VerifyingKey};
use ajar_connector_common::nats;
use anyhow::Context;
use futures_util::StreamExt;
use serde::Deserialize;
use store::{Audit, Store};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

#[derive(Debug, Deserialize)]
struct Config {
    nats_url: String,
    #[serde(default = "default_subject")]
    subject: String,
    database: String,
    /// `source_id` to 64-character hex verifying key.
    #[serde(default)]
    sources: HashMap<String, String>,
    /// Directory of `<source_id>.pub` files merged into `sources` at startup.
    #[serde(default)]
    sources_dir: Option<String>,
    #[serde(default)]
    cot: Option<CotConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct CotConfig {
    multicast: String,
    /// IPv4 address of the interface the TAK clients share.
    interface: Option<String>,
}

impl Default for CotConfig {
    fn default() -> Self {
        CotConfig {
            multicast: cot_out::DEFAULT_GROUP.to_string(),
            interface: None,
        }
    }
}

fn default_subject() -> String {
    "ajar.ingest.>".to_string()
}

impl Config {
    fn load(path: &str) -> anyhow::Result<Config> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading config {path}"))?;
        toml::from_str(&text).with_context(|| format!("parsing config {path}"))
    }

    /// The `[sources]` table merged with the `<source_id>.pub` files in
    /// `sources_dir`, decoded once so a malformed key fails at startup.
    fn keys(&self) -> anyhow::Result<HashMap<String, VerifyingKey>> {
        let mut keys = HashMap::new();
        for (source, hex_key) in &self.sources {
            let key = decode_key(hex_key).with_context(|| format!("key for {source}"))?;
            keys.insert(source.clone(), key);
        }
        let Some(dir) = &self.sources_dir else {
            return Ok(keys);
        };
        for entry in std::fs::read_dir(dir).with_context(|| format!("reading sources_dir {dir}"))? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("pub") {
                continue;
            }
            let source = path
                .file_stem()
                .and_then(|s| s.to_str())
                .ok_or_else(|| anyhow::anyhow!("unreadable name in {dir}"))?
                .to_string();
            let key = decode_key(&std::fs::read_to_string(&path)?)
                .with_context(|| path.display().to_string())?;
            tracing::info!(source = %source, file = %path.display(), "registered from sources_dir");
            keys.insert(source, key);
        }
        Ok(keys)
    }
}

fn decode_key(hex_key: &str) -> anyhow::Result<VerifyingKey> {
    let raw = hex::decode(hex_key.trim()).context("not hex")?;
    let bytes = <[u8; 32]>::try_from(raw.as_slice()).context("not 32 bytes")?;
    VerifyingKey::from_bytes(&bytes).context("not a valid Ed25519 key")
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,async_nats=warn".into()),
        )
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.as_slice() {
        [command, path] if command == "run" => run(path).await,
        [command, path] if command == "audit" => audit(path),
        [command, path] if command == "stats" => stats(path),
        [command, _] if command == "mint" => {
            Err(anyhow::anyhow!("usage: ajar-sink mint <source_id> <dir>"))
        }
        [command, source_id, dir] if command == "mint" => mint(source_id, dir),
        [other, _] => Err(anyhow::anyhow!("unknown command {other}")),
        _ => {
            eprintln!(
                "usage: ajar-sink <run|audit|stats> <config.toml>  |  mint <source_id> <dir>"
            );
            return ExitCode::FAILURE;
        }
    };

    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("ajar-sink: {e:#}");
            ExitCode::FAILURE
        }
    }
}

/// Subscribe and record until interrupted.
async fn run(path: &str) -> anyhow::Result<bool> {
    let cfg = Config::load(path)?;
    let keys = cfg.keys()?;
    if keys.is_empty() {
        anyhow::bail!(
            "no sources registered ([sources] table or sources_dir): every event would be refused"
        );
    }
    let mut store = Store::open(Path::new(&cfg.database))?;

    // Compose overlays that move the sink onto the host network can't resolve
    // the bus's compose DNS name.
    let nats_url = std::env::var("AJAR_SINK_NATS_URL").unwrap_or_else(|_| cfg.nats_url.clone());
    let client = nats::connect(&nats_url).await?;
    let mut sub = client.subscribe(cfg.subject.clone()).await?;
    tracing::info!(
        subject = %cfg.subject,
        database = %cfg.database,
        sources = keys.len(),
        held = store.count()?,
        "sink ready"
    );

    let cot = match &cfg.cot {
        Some(c) => {
            let out = cot_out::CotOut::open(&c.multicast, c.interface.as_deref())?;
            tracing::info!(group = %c.multicast, "rendering verified events as cot");
            Some(out)
        }
        None => None,
    };

    let (mut accepted, mut refused) = (0u64, 0u64);
    loop {
        tokio::select! {
            message = sub.next() => {
                let Some(message) = message else {
                    tracing::warn!("subscription ended");
                    break;
                };
                match store::accept(&message.payload, &keys) {
                    Ok(event) => {
                        let received_at = rfc3339_s(OffsetDateTime::now_utc())?;
                        let appended = store.append(&message.payload, &event, &received_at)?;
                        accepted += 1;
                        tracing::debug!(
                            seq = appended.seq,
                            source = %event.source_id,
                            entity = %event.entity_type,
                            hash = %hex::encode(appended.record_hash),
                            "recorded"
                        );
                        if let Some(out) = &cot {
                            // The record is already durable; a failed map render
                            // never stops recording.
                            if let Err(e) = out.send(&event) {
                                tracing::debug!(error = %e, "cot render skipped");
                            }
                        }
                        if accepted % 100 == 0 {
                            tracing::info!(accepted, refused, "recording");
                        }
                    }
                    Err(reason) => {
                        refused += 1;
                        tracing::warn!(subject = %message.subject, %reason, "refused");
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("shutting down");
                break;
            }
        }
    }

    let head = store.head()?;
    tracing::info!(
        accepted,
        refused,
        held = store.count()?,
        head = %hex::encode(head),
        "sink stopped"
    );
    Ok(true)
}

/// Re-verify every signature and every link, from the stored bytes alone.
fn audit(path: &str) -> anyhow::Result<bool> {
    let cfg = Config::load(path)?;
    let store = Store::open_existing(Path::new(&cfg.database))?;
    match store.audit(&cfg.keys()?)? {
        Audit::Intact { records, head } => {
            println!("audit: INTACT");
            println!("records: {records}");
            println!("head: {}", hex::encode(head));
            println!();
            println!("Every record verified under its publisher's key, and every link");
            println!("matches. No record has been added, removed, reordered or edited.");
            Ok(true)
        }
        Audit::Broken { seq, reason } => {
            println!("audit: BROKEN");
            println!("first failure at record {seq}: {reason}");
            Ok(false)
        }
    }
}

/// Mint a demo keypair: `<dir>/<source_id>.seed` (private, 0600) and
/// `<dir>/<source_id>.pub` (hex, what the sink registers). An existing seed is
/// kept, so a restart does not rotate identity under a running stack.
fn mint(source_id: &str, dir: &str) -> anyhow::Result<bool> {
    let seed_path = Path::new(dir).join(format!("{source_id}.seed"));
    let pub_path = Path::new(dir).join(format!("{source_id}.pub"));
    if seed_path.exists() {
        println!("mint: {} already exists, keeping it", seed_path.display());
        return Ok(true);
    }
    std::fs::create_dir_all(dir)?;

    let mut seed = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut seed))
        .context("reading /dev/urandom")?;
    let key = SigningKey::from_bytes(&seed);

    std::fs::write(&seed_path, seed)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&seed_path, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::write(&pub_path, hex::encode(key.verifying_key().to_bytes()))?;
    println!(
        "mint: {} (private) and {} (registered by the sink)",
        seed_path.display(),
        pub_path.display()
    );
    Ok(true)
}

fn stats(path: &str) -> anyhow::Result<bool> {
    let cfg = Config::load(path)?;
    let store = Store::open_existing(Path::new(&cfg.database))?;
    println!("database: {}", cfg.database);
    println!("records: {}", store.count()?);
    println!("head: {}", hex::encode(store.head()?));
    let by_source = store.by_source()?;
    if !by_source.is_empty() {
        println!();
        println!("{:<28} records", "source_id");
        for (source, count) in by_source {
            println!("{source:<28} {count}");
        }
    }
    Ok(true)
}

/// The sink's receive time, whole seconds in UTC. Kept apart from the
/// publisher's timestamp, which is its observation time and untrusted for
/// ordering.
fn rfc3339_s(at: OffsetDateTime) -> anyhow::Result<String> {
    Ok(at.replace_nanosecond(0)?.format(&Rfc3339)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_HEX: &str = "e28a8970753332bd72fef413e6b0b2ef1b4aadda7aa2c141f233712a6876b351";

    fn config(sources: &str) -> Config {
        toml::from_str(&format!(
            r#"
            nats_url = "nats://127.0.0.1:4222"
            database = "/tmp/sink.db"
            {sources}
            "#
        ))
        .unwrap()
    }

    #[test]
    fn subject_defaults_to_every_connector() {
        let cfg = config("");
        assert_eq!(cfg.subject, "ajar.ingest.>");
        assert!(cfg.sources.is_empty());
    }

    #[test]
    fn empty_cot_section_uses_the_mesh_sa_group() {
        let cot = config("[cot]").cot.unwrap();
        assert_eq!(cot.multicast, cot_out::DEFAULT_GROUP);
        assert!(cot.interface.is_none());
    }

    #[test]
    fn valid_key_decodes() {
        let cfg = config(&format!("[sources]\n\"acme-radar-1\" = \"{KEY_HEX}\""));
        assert_eq!(cfg.keys().unwrap().len(), 1);
    }

    #[test]
    fn non_hex_key_is_refused() {
        let cfg = config("[sources]\n\"acme-radar-1\" = \"not-hex\"");
        assert!(cfg.keys().is_err());
    }

    #[test]
    fn receive_time_is_whole_second_rfc3339() {
        let ts = rfc3339_s(OffsetDateTime::now_utc()).unwrap();
        assert_eq!(ts.len(), 20, "{ts}");
        assert!(ts.ends_with('Z'));
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[10..11], "T");
    }

    #[test]
    fn receive_time_matches_known_dates() {
        for (days, want) in [
            (0, "1970-01-01T00:00:00Z"),
            (19_000, "2022-01-08T00:00:00Z"),
            (18_321, "2020-02-29T00:00:00Z"),
            (18_322, "2020-03-01T00:00:00Z"),
        ] {
            let at = OffsetDateTime::from_unix_timestamp(days * 86_400).unwrap();
            assert_eq!(rfc3339_s(at).unwrap(), want);
        }
    }
}
