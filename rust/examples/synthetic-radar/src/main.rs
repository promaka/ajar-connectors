// SPDX-License-Identifier: Apache-2.0
//
//! Synthetic radar: stream a realistic **multi-domain** picture (air, surface,
//! ground) of canonical `mim:` tracks into an Ajar Core over NATS, so an operator
//! can watch the full governed path `connector -> NATS -> Core -> audit + egress`
//! render live on the Vantage map.
//!
//! Each track follows a looping waypoint route and carries a stable identity so a
//! consumer correlates observations into one track: a governed **`callsign`**
//! (its native track key — a callsign / hull id) is the correlation key the console
//! trails, and the same value rides in `source_uid` metadata for provenance.
//! Domain-conveying `entity_type` (`mim:aircraft` / `mim:vessel` /
//! `mim:land-vehicle`) drives correct symbology, and a `hostility` attribute
//! colours friend/hostile/neutral.
//!
//! The shape every connector follows is the three steps in the loop:
//!   1. normalize a native observation into a canonical Event (here synthesised),
//!   2. seal it (detached Ed25519 signature ++ canonical bytes),
//!   3. publish the sealed bytes to the connector's NATS ingest subject.
//!
//! ## Run
//!
//! ```text
//! cargo run -p synthetic-radar                 # dev: plaintext localhost NATS
//! cargo run -p synthetic-radar -- --dry-run    # build+seal+print, no NATS
//! ```
//!
//! Env: `NATS_URL`, `AJAR_SOURCE_ID` (connector identity, default `demo-radar`),
//! `AJAR_INGEST_PREFIX`, `AJAR_RATE_PER_MIN` (records/min, default 600),
//! `AJAR_SIGNING_SEED` (32-byte Ed25519 signing seed; required unless --dry-run),
//! `AJAR_TLS_CA` / `AJAR_TLS_CERT` / `AJAR_TLS_KEY` (enable mTLS),
//! `AJAR_HEALTH_ADDR` (Prometheus `/metrics` + `/healthz`).

use std::env;
use std::error::Error;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ajar_connector::{canonical_bytes, seal, EventBuilder, SigningKey};

/// Dev-only fallback signing seed: 32 bytes of `0x03` (documented TEST seed).
/// Reachable only under `--dry-run`; publishing requires `AJAR_SIGNING_SEED`.
const DEV_SEED: [u8; 32] = [0x03; 32];

#[derive(Default)]
struct Metrics {
    published: AtomicU64,
    publish_errors: AtomicU64,
}

/// The three domains this feed renders, each a canonical `mim:` type that drives
/// the console's symbology.
#[derive(Clone, Copy)]
enum Domain {
    Air,
    Surface,
    Ground,
}

impl Domain {
    fn entity_type(self) -> &'static str {
        match self {
            Domain::Air => "mim:aircraft",
            Domain::Surface => "mim:vessel",
            Domain::Ground => "mim:land-vehicle",
        }
    }
}

/// A synthetic track following a looping waypoint route (a patrol/orbit, not
/// random motion). Each tick it advances along the current leg, then turns to the
/// next waypoint on arrival.
struct Track {
    /// Native track key — rides in `source_uid` metadata; the console's stable id.
    uid: String,
    domain: Domain,
    hostility: &'static str,
    route: Vec<(f64, f64)>, // waypoints (lat, lon)
    leg: usize,
    lat: f64,
    lon: f64,
    alt_m: f64,
    step_deg: f64, // ground speed, degrees per sweep
}

impl Track {
    fn advance(&mut self) {
        let (tlat, tlon) = self.route[self.leg];
        let (dlat, dlon) = (tlat - self.lat, tlon - self.lon);
        let dist = (dlat * dlat + dlon * dlon).sqrt();
        if dist <= self.step_deg || dist == 0.0 {
            self.lat = tlat;
            self.lon = tlon;
            self.leg = (self.leg + 1) % self.route.len();
        } else {
            self.lat += dlat / dist * self.step_deg;
            self.lon += dlon / dist * self.step_deg;
        }
    }

    /// A diamond racetrack centred on `(cx, cy)` with radius `r`.
    fn racetrack(cx: f64, cy: f64, r: f64) -> Vec<(f64, f64)> {
        vec![(cx + r, cy), (cx, cy + r), (cx - r, cy), (cx, cy - r)]
    }
}

/// Builds a realistic mixed order of battle over the Gulf: airborne CAP/AWACS,
/// surface combatants + merchant traffic, and a coastal ground patrol. Stable,
/// hand-picked track keys and hostilities so the picture reads like a real feed.
fn make_tracks() -> Vec<Track> {
    // (uid, domain, hostility, centre lat, centre lon, radius, altitude m, step)
    #[rustfmt::skip]
    #[allow(clippy::type_complexity)]
    let defs: &[(&str, Domain, &str, f64, f64, f64, f64, f64)] = &[
        // Air
        ("QTR41", Domain::Air, "Friend", 25.6, 51.2, 0.22, 10600.0, 0.030),
        ("IAF221", Domain::Air, "Friend", 26.2, 50.6, 0.18, 9100.0, 0.026),
        ("AWACS1", Domain::Air, "Friend", 26.0, 50.9, 0.30, 9800.0, 0.018),
        ("UNK07", Domain::Air, "Unknown", 26.7, 52.0, 0.15, 7300.0, 0.034),
        ("HOSTILE9", Domain::Air, "Hostile", 27.0, 52.3, 0.20, 6100.0, 0.038),
        ("9HA4721", Domain::Air, "Neutral", 25.3, 51.6, 0.24, 11200.0, 0.028),
        // Surface
        ("HMS-DARING", Domain::Surface, "Friend", 25.9, 50.3, 0.10, 0.0, 0.006),
        ("USS-COLE", Domain::Surface, "Friend", 26.1, 50.1, 0.08, 0.0, 0.005),
        ("IRIS-JAMARAN", Domain::Surface, "Hostile", 26.6, 51.4, 0.09, 0.0, 0.006),
        ("MV-SHERE", Domain::Surface, "Neutral", 25.5, 50.5, 0.14, 0.0, 0.004),
        ("MT-PATROL3", Domain::Surface, "Unknown", 26.4, 50.8, 0.07, 0.0, 0.005),
        // Ground (coastal)
        ("SAM-SKORP1", Domain::Ground, "Hostile", 26.9, 51.9, 0.04, 15.0, 0.002),
        ("PATROL-V7", Domain::Ground, "Friend", 25.7, 50.2, 0.06, 20.0, 0.003),
        ("CONVOY-ZZ", Domain::Ground, "Friend", 25.4, 50.35, 0.05, 12.0, 0.0025),
    ];
    defs.iter()
        .map(|&(uid, domain, aff, cx, cy, r, alt, step)| {
            let route = Track::racetrack(cx, cy, r);
            let (lat, lon) = route[0];
            Track {
                uid: uid.to_string(),
                domain,
                hostility: aff,
                route,
                leg: 1,
                lat,
                lon,
                alt_m: alt,
                step_deg: step,
            }
        })
        .collect()
}

/// Whether this invocation publishes nothing. Publishing is the default, so an
/// unrecognised or misspelled flag leaves the connector publishing rather than
/// silently entering a mode where the dev seed becomes reachable.
fn is_dry_run(args: &[String]) -> bool {
    args.iter().any(|a| a == "--dry-run")
}

fn flag_value(args: &[String], name: &str) -> Option<String> {
    let i = args.iter().position(|a| a == name)?;
    args.get(i + 1).cloned()
}

fn env_f64(key: &str, default: f64) -> f64 {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Loads the Ed25519 signing seed from the file named by `AJAR_SIGNING_SEED` —
/// the same variable every connector template and the Helm chart use. The file is
/// either 32 raw bytes or the 64 hex characters `ajar keygen` writes (surrounding
/// whitespace tolerated); this is how the connector assumes its **registered
/// identity**, and the seed's public half must be in Core's registry.
///
/// The dev seed is reachable only under `--dry-run`, where nothing is published.
/// Publishing without a real seed is refused rather than silently signed with a
/// key whose private half is in this repository.
fn load_seed(dry_run: bool) -> Result<[u8; 32], Box<dyn Error>> {
    match seed_source(dry_run, env::var("AJAR_SIGNING_SEED").ok().as_deref()) {
        SeedSource::File(path) => {
            let bytes = std::fs::read(&path)
                .map_err(|e| format!("read AJAR_SIGNING_SEED {path}: {e}"))?;
            parse_seed(&bytes).ok_or_else(|| {
                format!(
                    "seed file {path}: expected 32 raw bytes or 64 hex chars, got {} bytes",
                    bytes.len()
                )
                .into()
            })
        }
        SeedSource::Dev => {
            eprintln!("[synthetic-radar] no AJAR_SIGNING_SEED — using the dev seed (dry-run only)");
            Ok(DEV_SEED)
        }
        SeedSource::Refuse => Err(
            "set AJAR_SIGNING_SEED to your 32-byte key file (see scripts/gen-connector-key.sh). \
             The dev seed is a published test key and is never used for publishing."
                .into(),
        ),
    }
}

/// Where the signing seed comes from. Decided before any I/O and with no
/// environment access, so the rule that matters — the dev seed is unreachable
/// whenever events are published — is a pure function that can be checked
/// exhaustively rather than a branch nobody exercises.
#[derive(Debug, PartialEq, Eq)]
enum SeedSource {
    /// Read the seed from this path.
    File(String),
    /// The published test seed. Only ever selected when nothing is published.
    Dev,
    /// No seed and events would be published: refuse rather than sign.
    Refuse,
}

fn seed_source(dry_run: bool, configured: Option<&str>) -> SeedSource {
    match configured {
        Some(path) if !path.is_empty() => SeedSource::File(path.to_string()),
        _ if dry_run => SeedSource::Dev,
        _ => SeedSource::Refuse,
    }
}

/// A signing seed is 32 raw bytes, or the 64 hex characters `ajar keygen` writes
/// (with optional surrounding whitespace). Fails closed on anything else.
fn parse_seed(bytes: &[u8]) -> Option<[u8; 32]> {
    if let Ok(raw) = <[u8; 32]>::try_from(bytes) {
        return Some(raw);
    }
    let decoded = hex::decode(std::str::from_utf8(bytes).ok()?.trim()).ok()?;
    decoded.try_into().ok()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    let dry_run = is_dry_run(&args);
    let max_ticks: Option<u64> = flag_value(&args, "--ticks").and_then(|v| v.parse().ok());

    let source_id = env::var("AJAR_SOURCE_ID").unwrap_or_else(|_| "demo-radar".to_string());
    let prefix = env::var("AJAR_INGEST_PREFIX").unwrap_or_else(|_| "ajar.ingest".to_string());
    let nats_url = env::var("NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:4222".to_string());
    let rate_per_min = env_f64("AJAR_RATE_PER_MIN", 600.0).max(1.0);

    let mut tracks = make_tracks();
    let n_tracks = tracks.len();

    // One "sweep" emits a position for every track. Pick the sweep interval so
    // `n_tracks * sweeps_per_sec` hits the requested records/minute.
    let sweeps_per_sec = (rate_per_min / 60.0) / n_tracks as f64;
    let interval = Duration::from_secs_f64((1.0 / sweeps_per_sec).clamp(0.05, 5.0));

    let subject = format!("{prefix}.{source_id}");
    let key = SigningKey::from_bytes(&load_seed(dry_run)?);

    let metrics = Arc::new(Metrics::default());
    spawn_health(metrics.clone());

    let client = if dry_run {
        eprintln!("[synthetic-radar] --dry-run: building + sealing, not publishing");
        None
    } else {
        eprintln!("[synthetic-radar] connecting to NATS at {nats_url}");
        Some(nats_connect(&nats_url).await?)
    };

    eprintln!(
        "[synthetic-radar] source_id={source_id}  subject={subject}\n\
         [synthetic-radar] {n_tracks} tracks (air/surface/ground), target ~{rate_per_min:.0} records/min\n\
         [synthetic-radar] canonical mim: types + governed callsign (correlation key) + hostility. Ctrl-C to stop."
    );

    let start = Instant::now();
    let mut last_report = Instant::now();
    let mut total: u64 = 0;
    let mut tick: u64 = 0;

    loop {
        for track in tracks.iter_mut() {
            track.advance();

            // 1. normalize (synthesised). Every event carries the track's stable
            //    identity so a consumer correlates observations into one track:
            //    `callsign` (a governed attribute on the platform types) is the
            //    human-readable id, and the same native key rides in `source_uid`
            //    metadata for provenance. Without a governed identity a consumer sees
            //    every observation as a new track.
            let mut builder = EventBuilder::new(&source_id, track.domain.entity_type())
                .new_id()
                .now()
                .location(track.lat, track.lon, track.alt_m)
                .confidence(0.9)
                .policy_tag("air-defence")
                .attribute("hostility", track.hostility)
                .attribute("callsign", &track.uid)
                .metadata("source_uid", &track.uid);
            // A vessel's domain is an attribute now that surface and subsurface
            // share one entity type.
            if let Domain::Surface = track.domain {
                builder = builder.attribute("vessel_domain", "Surface");
            }
            let event = builder.build()?;

            // 2. seal, 3. publish
            let sealed = seal(&canonical_bytes(&event), &key);
            if let Some(client) = &client {
                if let Err(e) = client
                    .publish(subject.clone(), bytes::Bytes::from(sealed))
                    .await
                {
                    eprintln!("[synthetic-radar] publish error (continuing): {e}");
                    metrics.publish_errors.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            }
            total += 1;
            metrics.published.fetch_add(1, Ordering::Relaxed);
        }

        if let Some(client) = &client {
            client.flush().await?;
        }

        if max_ticks.is_some() || last_report.elapsed() >= Duration::from_secs(1) {
            let secs = start.elapsed().as_secs_f64().max(0.001);
            let sample = &tracks[0];
            eprintln!(
                "[+{:>4.0}s] {} tracks  published {:>7} events  (~{:.0}/min)  e.g. {} {} @ {:.3},{:.3} {:.0}m{}",
                secs,
                n_tracks,
                total,
                total as f64 / secs * 60.0,
                sample.uid,
                sample.domain.entity_type(),
                sample.lat,
                sample.lon,
                sample.alt_m,
                if client.is_some() { "" } else { "  [dry-run]" },
            );
            last_report = Instant::now();
        }

        tick += 1;
        if max_ticks.is_some_and(|m| tick >= m) {
            break;
        }
        tokio::time::sleep(interval).await;
    }

    Ok(())
}

/// Connects to NATS, enabling **mTLS** when `AJAR_TLS_CA` / `AJAR_TLS_CERT` /
/// `AJAR_TLS_KEY` are all set (production; client-cert CN = `source_id`). Unset →
/// plaintext for local dev.
async fn nats_connect(url: &str) -> Result<async_nats::Client, async_nats::ConnectError> {
    let mut opts = async_nats::ConnectOptions::new().retry_on_initial_connect();
    match (
        env::var("AJAR_TLS_CA"),
        env::var("AJAR_TLS_CERT"),
        env::var("AJAR_TLS_KEY"),
    ) {
        (Ok(ca), Ok(cert), Ok(key)) if !ca.is_empty() && !cert.is_empty() && !key.is_empty() => {
            eprintln!("[synthetic-radar] mTLS enabled (client cert = source identity)");
            opts = opts
                .require_tls(true)
                .add_root_certificates(ca.into())
                .add_client_certificate(cert.into(), key.into());
        }
        _ => eprintln!("[synthetic-radar] no AJAR_TLS_* set — connecting without TLS (dev only)"),
    }
    opts.connect(url).await
}

/// Spawns a tiny health/metrics HTTP endpoint when `AJAR_HEALTH_ADDR` is set.
/// `GET /healthz` → liveness; `GET /metrics` → Prometheus text.
fn spawn_health(metrics: Arc<Metrics>) {
    let addr = match env::var("AJAR_HEALTH_ADDR") {
        Ok(a) if !a.is_empty() => a,
        _ => return,
    };
    std::thread::spawn(move || {
        use std::io::{Read, Write};
        let listener = match std::net::TcpListener::bind(&addr) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[synthetic-radar] health endpoint disabled: bind {addr}: {e}");
                return;
            }
        };
        eprintln!("[synthetic-radar] health/metrics on http://{addr}/healthz and /metrics");
        for stream in listener.incoming().flatten() {
            let mut stream = stream;
            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]);
            let path = req.split_whitespace().nth(1).unwrap_or("/");
            let body = if path.starts_with("/metrics") {
                format!(
                    "# TYPE ajar_connector_published_total counter\n\
                     ajar_connector_published_total {}\n\
                     # TYPE ajar_connector_publish_errors_total counter\n\
                     ajar_connector_publish_errors_total {}\n",
                    metrics.published.load(Ordering::Relaxed),
                    metrics.publish_errors.load(Ordering::Relaxed),
                )
            } else {
                "ok\n".to_string()
            };
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(resp.as_bytes());
        }
    });
}

#[cfg(test)]
mod tests {
    use super::{is_dry_run, seed_source, SeedSource};

    fn argv(parts: &[&str]) -> Vec<String> {
        std::iter::once("synthetic-radar".to_string())
            .chain(parts.iter().map(|s| s.to_string()))
            .collect()
    }

    /// The one rule that matters: nothing may both sign with the published test
    /// seed and publish. Checked over every flag arrangement crossed with every
    /// state the seed variable can be in, rather than trusting one branch.
    #[test]
    fn no_invocation_both_signs_with_the_dev_seed_and_publishes() {
        let flag_sets: &[&[&str]] = &[
            &[],
            &["--ticks", "1"],
            &["--dry-run"],
            &["--dry-run", "--ticks", "1"],
            &["--ticks", "1", "--dry-run"],
            &["--rate", "600"],
            // Near-misses: none of these may be mistaken for --dry-run, because
            // being wrong here puts the dev seed on a publishing path.
            &["--dry_run"],
            &["--dryrun"],
            &["-dry-run"],
            &["--dry-run=true"],
            &["--DRY-RUN"],
            &["--ticks", "--dry-run"],
        ];
        let seed_states: &[Option<&str>] = &[None, Some(""), Some("/etc/ajar/seed")];

        for flags in flag_sets {
            let args = argv(flags);
            let dry = is_dry_run(&args);
            for configured in seed_states {
                let source = seed_source(dry, *configured);
                if !dry {
                    assert_ne!(
                        source,
                        SeedSource::Dev,
                        "{flags:?} with seed {configured:?} publishes but selected the dev seed"
                    );
                }
                // And the converse worth stating: a configured seed always wins,
                // so --dry-run never quietly discards a real key.
                if matches!(configured, Some(p) if !p.is_empty()) {
                    assert!(matches!(source, SeedSource::File(_)));
                }
            }
        }
    }

    #[test]
    fn publishing_without_a_seed_is_refused_not_defaulted() {
        assert_eq!(seed_source(false, None), SeedSource::Refuse);
        assert_eq!(seed_source(false, Some("")), SeedSource::Refuse);
    }

    #[test]
    fn the_dev_seed_is_reachable_only_in_dry_run() {
        assert_eq!(seed_source(true, None), SeedSource::Dev);
        assert_eq!(seed_source(true, Some("")), SeedSource::Dev);
    }

    #[test]
    fn only_the_exact_flag_means_dry_run() {
        assert!(is_dry_run(&argv(&["--dry-run"])));
        for near in ["--dry_run", "--dryrun", "-dry-run", "--DRY-RUN", "--dry-run=true"] {
            assert!(!is_dry_run(&argv(&[near])), "{near} must not enable dry-run");
        }
    }

    use super::parse_seed;

    #[test]
    fn accepts_32_raw_bytes() {
        let raw = [7u8; 32];
        assert_eq!(parse_seed(&raw), Some(raw));
    }

    #[test]
    fn accepts_64_hex_from_ajar_keygen() {
        // What `ajar keygen` writes: 64 hex chars, here with a trailing newline.
        let file = format!("{}\n", "03".repeat(32));
        assert_eq!(parse_seed(file.as_bytes()), Some([0x03u8; 32]));
    }

    #[test]
    fn rejects_wrong_length() {
        assert_eq!(parse_seed(b"tooshort"), None);
        assert_eq!(parse_seed(&[0u8; 31]), None);
    }
}
