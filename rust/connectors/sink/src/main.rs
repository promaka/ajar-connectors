// SPDX-License-Identifier: Apache-2.0
//! `ajar-sink` — subscribe to sealed events, verify them, persist them, and be
//! able to prove afterwards that the record was not altered.
//!
//! This exists so the whole path can be run and inspected without Ajar Core:
//! start NATS, start any number of connectors, start this, and every event that
//! arrives is checked against its publisher's registered key and appended to a
//! hash-chained SQLite database. `ajar-sink audit` then recomputes every
//! signature and every link from the stored bytes.
//!
//! **It is not Ajar Core.** There is no policy engine, no ontology validation, no
//! classification handling and no releasability. It answers "did this publisher
//! send exactly these events, and is the record complete" — which is what a
//! development loop, a bench measurement and a partner evaluation need. Deciding
//! what an event is *allowed* to be is Core's job and stays there.
//!
//! ```text
//! ajar-sink run   sink.toml     # subscribe, verify, persist
//! ajar-sink audit sink.toml     # re-verify the whole chain
//! ajar-sink stats sink.toml     # what is held, per source
//! ```

mod store;

use std::collections::HashMap;
use std::process::ExitCode;

use ajar_connector::VerifyingKey;
use ajar_connector_common::nats;
use futures_util::StreamExt;
use serde::Deserialize;
use store::{Audit, Store};

/// What the sink connects to, keeps, and trusts.
#[derive(Debug, Deserialize)]
struct Config {
    /// NATS URL. `AJAR_TLS_*` in the environment enables mTLS, exactly as it does
    /// for a connector.
    nats_url: String,
    /// Subject to subscribe. The default takes every connector on the bus.
    #[serde(default = "default_subject")]
    subject: String,
    /// SQLite file the chain is written to.
    database: String,
    /// `source_id` to 64-character hex verifying key. A publisher absent from
    /// this table is refused: an event nobody can verify is worse than no event.
    #[serde(default)]
    sources: HashMap<String, String>,
    /// Optional directory of `<source_id>.pub` files (64-char hex) merged into
    /// the registry at startup. For stacks that mint their keys on first run.
    #[serde(default)]
    sources_dir: Option<String>,
}

fn default_subject() -> String {
    "ajar.ingest.>".to_string()
}

impl Config {
    fn load(path: &str) -> anyhow::Result<Config> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("reading config {path}: {e}"))?;
        toml::from_str(&text).map_err(|e| anyhow::anyhow!("parsing config {path}: {e}"))
    }

    /// Decode the configured keys once, so a malformed key is a startup failure
    /// rather than a per-event surprise.
    /// Merge the [sources] table with any `<source_id>.pub` files in
    /// `sources_dir`. The directory form exists for the demo stack, where the
    /// keypair is minted at startup so no key value lives in the repository; a
    /// production registry is the operator's [sources] table, or Ajar Core.
    fn all_keys(&self) -> anyhow::Result<HashMap<String, VerifyingKey>> {
        let mut keys = self.keys()?;
        if let Some(dir) = &self.sources_dir {
            for entry in std::fs::read_dir(dir)
                .map_err(|e| anyhow::anyhow!("reading sources_dir {dir}: {e}"))?
            {
                let path = entry?.path();
                if path.extension().and_then(|e| e.to_str()) != Some("pub") {
                    continue;
                }
                let source = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .ok_or_else(|| anyhow::anyhow!("unreadable name in {dir}"))?
                    .to_string();
                let hex_key = std::fs::read_to_string(&path)?;
                let bytes = hex::decode(hex_key.trim())
                    .map_err(|e| anyhow::anyhow!("{}: not hex: {e}", path.display()))?;
                let arr: [u8; 32] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("{}: not 32 bytes", path.display()))?;
                let key = VerifyingKey::from_bytes(&arr)
                    .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
                tracing::info!(source = %source, file = %path.display(), "registered from sources_dir");
                keys.insert(source, key);
            }
        }
        Ok(keys)
    }

    fn keys(&self) -> anyhow::Result<HashMap<String, VerifyingKey>> {
        let mut out = HashMap::new();
        for (source, hex_key) in &self.sources {
            let raw = hex::decode(hex_key.trim())
                .map_err(|e| anyhow::anyhow!("key for {source} is not hex: {e}"))?;
            let bytes: [u8; 32] = raw
                .try_into()
                .map_err(|_| anyhow::anyhow!("key for {source} must be 32 bytes"))?;
            let key = VerifyingKey::from_bytes(&bytes)
                .map_err(|e| anyhow::anyhow!("key for {source} is not a valid Ed25519 key: {e}"))?;
            out.insert(source.clone(), key);
        }
        Ok(out)
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let (command, path) = match args.as_slice() {
        [command, path] => (command.as_str(), path.as_str()),
        // mint takes a third argument, the directory.
        [command, source, _dir] if command == "mint" => (command.as_str(), source.as_str()),
        _ => {
            eprintln!(
                "usage: ajar-sink <run|audit|stats> <config.toml>  |  mint <source_id> <dir>"
            );
            return ExitCode::FAILURE;
        }
    };

    let result = match command {
        "run" => run(path).await,
        "audit" => audit(path),
        "stats" => stats(path),
        // mint <source_id> <dir>: for the demo stack. `path` is the source_id
        // here, and the directory follows it.
        "mint" => mint(path, std::env::args().nth(3).as_deref()),
        other => Err(anyhow::anyhow!("unknown command {other}")),
    };

    match result {
        Ok(ok) => {
            if ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(e) => {
            eprintln!("ajar-sink: {e:#}");
            ExitCode::FAILURE
        }
    }
}

/// Subscribe and record until interrupted.
async fn run(path: &str) -> anyhow::Result<bool> {
    let cfg = Config::load(path)?;
    let keys = cfg.all_keys()?;
    if keys.is_empty() {
        anyhow::bail!(
            "no sources registered ([sources] table or sources_dir): every event would be refused"
        );
    }
    let mut store = Store::open(std::path::Path::new(&cfg.database))?;

    let client = nats::connect(&cfg.nats_url).await?;
    let mut sub = client.subscribe(cfg.subject.clone()).await?;
    tracing::info!(
        subject = %cfg.subject,
        database = %cfg.database,
        sources = keys.len(),
        held = store.count()?,
        "sink ready"
    );

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
                        let received_at = now_rfc3339();
                        let appended = store.append(&message.payload, &event, &received_at)?;
                        accepted += 1;
                        tracing::debug!(
                            seq = appended.seq,
                            source = %event.source_id,
                            entity = %event.entity_type,
                            hash = %hex::encode(appended.record_hash),
                            "recorded"
                        );
                        if accepted % 100 == 0 {
                            tracing::info!(accepted, refused, "recording");
                        }
                    }
                    Err(reason) => {
                        refused += 1;
                        // Refusals are counted and logged, never stored: the chain
                        // holds only events that verified.
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
    let store = Store::open_existing(std::path::Path::new(&cfg.database))?;
    match store.audit(&cfg.all_keys()?)? {
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

/// Mint a keypair for the demo stack: `<dir>/<source_id>.seed` (private, 0600)
/// and `<dir>/<source_id>.pub` (hex, what the sink registers). Exists so the
/// demo repository carries no key value at all; a real deployment generates
/// keys with scripts/gen-connector-key.sh and registers them with the operator.
/// Refuses to overwrite: a restart must not rotate identity under a running
/// stack.
fn mint(source_id: &str, dir: Option<&str>) -> anyhow::Result<bool> {
    let dir = dir.ok_or_else(|| anyhow::anyhow!("usage: ajar-sink mint <source_id> <dir>"))?;
    let seed_path = std::path::Path::new(dir).join(format!("{source_id}.seed"));
    let pub_path = std::path::Path::new(dir).join(format!("{source_id}.pub"));
    if seed_path.exists() {
        println!("mint: {} already exists, keeping it", seed_path.display());
        return Ok(true);
    }
    std::fs::create_dir_all(dir)?;

    let mut seed = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut seed))
        .map_err(|e| anyhow::anyhow!("reading /dev/urandom: {e}"))?;
    let key = ajar_connector::SigningKey::from_bytes(&seed);

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

/// Summarise what is held.
fn stats(path: &str) -> anyhow::Result<bool> {
    let cfg = Config::load(path)?;
    let store = Store::open_existing(std::path::Path::new(&cfg.database))?;
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

/// The sink's own clock, recorded alongside the publisher's timestamp. The two
/// are deliberately separate: the publisher's is its observation time and is
/// untrusted for ordering, this one is when the record entered the chain.
fn now_rfc3339() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Civil-time conversion without a date dependency: days since the epoch,
    // then the usual proleptic Gregorian arithmetic.
    let (days, rem) = ((secs / 86_400) as i64, secs % 86_400);
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, mo, d) = civil_from_days(days);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Howard Hinnant's days-from-civil inverse, the standard branch-free form.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_to_every_connector_on_the_bus() {
        let cfg: Config = toml::from_str(
            r#"
            nats_url = "nats://127.0.0.1:4222"
            database = "/tmp/sink.db"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.subject, "ajar.ingest.>");
        assert!(cfg.sources.is_empty());
    }

    #[test]
    fn keys_are_decoded_once_and_bad_ones_fail_at_startup() {
        let good = "e28a8970753332bd72fef413e6b0b2ef1b4aadda7aa2c141f233712a6876b351";
        let cfg: Config = toml::from_str(&format!(
            r#"
            nats_url = "nats://x:4222"
            database = "/tmp/sink.db"
            [sources]
            "acme-radar-1" = "{good}"
            "#
        ))
        .unwrap();
        assert_eq!(cfg.keys().unwrap().len(), 1);

        let bad: Config = toml::from_str(
            r#"
            nats_url = "nats://x:4222"
            database = "/tmp/sink.db"
            [sources]
            "acme-radar-1" = "not-hex"
            "#,
        )
        .unwrap();
        assert!(bad.keys().is_err());
    }

    #[test]
    fn timestamps_are_rfc3339() {
        let ts = now_rfc3339();
        assert_eq!(ts.len(), 20, "{ts}");
        assert!(ts.ends_with('Z'));
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[10..11], "T");
    }

    #[test]
    fn civil_conversion_matches_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_000), (2022, 1, 8));
        // A leap day, which is where naive conversions go wrong.
        assert_eq!(civil_from_days(18_321), (2020, 2, 29));
        assert_eq!(civil_from_days(18_322), (2020, 3, 1));
    }
}
