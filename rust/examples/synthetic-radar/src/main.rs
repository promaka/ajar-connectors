// SPDX-License-Identifier: Apache-2.0
//
//! Synthetic radar: streams air, surface and ground `mim:` tracks into an Ajar
//! Core over NATS. Each track loops a waypoint route and carries its key as the
//! governed `callsign` and as `source_uid` metadata, plus a `hostility`.
//! Environment variables and flags are listed in the README.

use std::env;
use std::error::Error;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ajar_connector::{EventBuilder, SigningKey, NATS_MSG_ID_HEADER};

#[derive(Default)]
struct Metrics {
    published: AtomicU64,
    publish_errors: AtomicU64,
}

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

/// A synthetic track that advances along a looping waypoint route.
struct Track {
    uid: String,
    domain: Domain,
    hostility: &'static str,
    /// Waypoints as (lat, lon).
    route: Vec<(f64, f64)>,
    leg: usize,
    lat: f64,
    lon: f64,
    alt_m: f64,
    /// Ground speed in degrees per sweep.
    step_deg: f64,
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
}

/// A mixed order of battle over the Gulf, each track on a diamond racetrack.
fn make_tracks() -> Vec<Track> {
    // (uid, domain, hostility, centre lat, centre lon, radius deg, altitude m, step deg)
    #[rustfmt::skip]
    #[allow(clippy::type_complexity)]
    let defs: &[(&str, Domain, &str, f64, f64, f64, f64, f64)] = &[
        ("QTR41", Domain::Air, "Friend", 25.6, 51.2, 0.22, 10600.0, 0.030),
        ("IAF221", Domain::Air, "Friend", 26.2, 50.6, 0.18, 9100.0, 0.026),
        ("AWACS1", Domain::Air, "Friend", 26.0, 50.9, 0.30, 9800.0, 0.018),
        ("UNK07", Domain::Air, "Unknown", 26.7, 52.0, 0.15, 7300.0, 0.034),
        ("HOSTILE9", Domain::Air, "Hostile", 27.0, 52.3, 0.20, 6100.0, 0.038),
        ("9HA4721", Domain::Air, "Neutral", 25.3, 51.6, 0.24, 11200.0, 0.028),
        ("HMS-DARING", Domain::Surface, "Friend", 25.9, 50.3, 0.10, 0.0, 0.006),
        ("USS-COLE", Domain::Surface, "Friend", 26.1, 50.1, 0.08, 0.0, 0.005),
        ("IRIS-JAMARAN", Domain::Surface, "Hostile", 26.6, 51.4, 0.09, 0.0, 0.006),
        ("MV-SHERE", Domain::Surface, "Neutral", 25.5, 50.5, 0.14, 0.0, 0.004),
        ("MT-PATROL3", Domain::Surface, "Unknown", 26.4, 50.8, 0.07, 0.0, 0.005),
        ("SAM-SKORP1", Domain::Ground, "Hostile", 26.9, 51.9, 0.04, 15.0, 0.002),
        ("PATROL-V7", Domain::Ground, "Friend", 25.7, 50.2, 0.06, 20.0, 0.003),
        ("CONVOY-ZZ", Domain::Ground, "Friend", 25.4, 50.35, 0.05, 12.0, 0.0025),
    ];
    defs.iter()
        .map(|&(uid, domain, hostility, cx, cy, r, alt_m, step_deg)| {
            let route = vec![(cx + r, cy), (cx, cy + r), (cx - r, cy), (cx, cy - r)];
            let (lat, lon) = route[0];
            Track {
                uid: uid.to_string(),
                domain,
                hostility,
                route,
                leg: 1,
                lat,
                lon,
                alt_m,
                step_deg,
            }
        })
        .collect()
}

/// Loads the Ed25519 seed named by `AJAR_SIGNING_SEED`, or mints an ephemeral
/// key under `--dry-run`, where nothing is published.
fn load_seed(dry_run: bool) -> Result<[u8; 32], Box<dyn Error>> {
    match seed_source(dry_run, env::var("AJAR_SIGNING_SEED").ok().as_deref()) {
        SeedSource::File(path) => {
            let bytes =
                std::fs::read(&path).map_err(|e| format!("read AJAR_SIGNING_SEED {path}: {e}"))?;
            parse_seed(&bytes).ok_or_else(|| {
                format!(
                    "seed file {path}: expected 32 raw bytes or 64 hex chars, got {} bytes",
                    bytes.len()
                )
                .into()
            })
        }
        SeedSource::Ephemeral => {
            eprintln!(
                "[synthetic-radar] no AJAR_SIGNING_SEED, minted an ephemeral throwaway key (dry-run only)"
            );
            let mut seed = [0u8; 32];
            std::fs::File::open("/dev/urandom")
                .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut seed))
                .expect("[synthetic-radar] reading /dev/urandom");
            Ok(seed)
        }
        SeedSource::Refuse => Err(
            "set AJAR_SIGNING_SEED to your 32-byte key file (see scripts/gen-connector-key.sh)"
                .into(),
        ),
    }
}

/// Where the signing seed comes from, decided without I/O so the rule that a
/// publishing run never signs with an ephemeral key is unit-tested.
#[derive(Debug, PartialEq, Eq)]
enum SeedSource {
    File(String),
    Ephemeral,
    Refuse,
}

fn seed_source(dry_run: bool, configured: Option<&str>) -> SeedSource {
    match configured {
        Some(path) if !path.is_empty() => SeedSource::File(path.to_string()),
        _ if dry_run => SeedSource::Ephemeral,
        _ => SeedSource::Refuse,
    }
}

/// A seed file is 32 raw bytes or the 64 hex characters `ajar keygen` writes,
/// surrounding whitespace tolerated.
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
    let dry_run = args.iter().any(|a| a == "--dry-run");
    let max_ticks: Option<u64> = args
        .iter()
        .position(|a| a == "--ticks")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok());

    let source_id = env::var("AJAR_SOURCE_ID").unwrap_or_else(|_| "demo-radar".to_string());
    let prefix = env::var("AJAR_INGEST_PREFIX").unwrap_or_else(|_| "ajar.ingest".to_string());
    let nats_url = env::var("NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:4222".to_string());
    let rate_per_min = env::var("AJAR_RATE_PER_MIN")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(600.0)
        .max(1.0);

    let mut tracks = make_tracks();
    let n_tracks = tracks.len();

    // One sweep emits a position for every track.
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

            // 1. Normalize (synthesised here). The governed `callsign` is what a consumer
            // correlates a track on.
            let mut builder = EventBuilder::new(&source_id, track.domain.entity_type())
                .new_id()
                .now()
                .location(track.lat, track.lon, track.alt_m)
                .confidence(0.9)
                .policy_tag("air-defence")
                .attribute("hostility", track.hostility)
                .attribute("callsign", &track.uid)
                .metadata("source_uid", &track.uid);
            // Surface and subsurface vessels share one entity type.
            if let Domain::Surface = track.domain {
                builder = builder.attribute("vessel_domain", "Surface");
            }
            let event = builder.build()?;

            // 2. Seal.
            let sealed = ajar_connector::seal(&ajar_connector::canonical_bytes(&event), &key);

            // 3. Publish.
            if let Some(client) = &client {
                let mut headers = async_nats::HeaderMap::new();
                // The event id lets the broker's duplicate window drop retransmissions.
                headers.insert(NATS_MSG_ID_HEADER, event.id.as_str());
                if let Err(e) = client
                    .publish_with_headers(subject.clone(), headers, bytes::Bytes::from(sealed))
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

/// Connects to NATS over mTLS when `AJAR_TLS_CA`, `AJAR_TLS_CERT` and
/// `AJAR_TLS_KEY` are all set, else in plaintext.
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
        _ => eprintln!("[synthetic-radar] no AJAR_TLS_* set, connecting without TLS (dev only)"),
    }
    opts.connect(url).await
}

/// Serves `GET /healthz` and Prometheus `GET /metrics` on `AJAR_HEALTH_ADDR`, if set.
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
    use super::{parse_seed, seed_source, SeedSource};

    #[test]
    fn publishing_without_seed_is_refused() {
        assert_eq!(seed_source(false, None), SeedSource::Refuse);
        assert_eq!(seed_source(false, Some("")), SeedSource::Refuse);
    }

    #[test]
    fn ephemeral_key_only_in_dry_run() {
        assert_eq!(seed_source(true, None), SeedSource::Ephemeral);
        assert_eq!(seed_source(true, Some("")), SeedSource::Ephemeral);
    }

    #[test]
    fn configured_seed_always_wins() {
        for dry_run in [false, true] {
            assert_eq!(
                seed_source(dry_run, Some("/etc/ajar/seed")),
                SeedSource::File("/etc/ajar/seed".to_string()),
                "dry_run={dry_run}"
            );
        }
    }

    #[test]
    fn accepts_32_raw_bytes() {
        let raw = [7u8; 32];
        assert_eq!(parse_seed(&raw), Some(raw));
    }

    #[test]
    fn accepts_64_hex_with_newline() {
        let file = format!("{}\n", "03".repeat(32));
        assert_eq!(parse_seed(file.as_bytes()), Some([0x03u8; 32]));
    }

    #[test]
    fn rejects_wrong_length() {
        assert_eq!(parse_seed(b"tooshort"), None);
        assert_eq!(parse_seed(&[0u8; 31]), None);
    }
}
