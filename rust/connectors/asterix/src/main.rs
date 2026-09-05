// SPDX-License-Identifier: Apache-2.0
//! ASTERIX ingress connector (CAT010 surface movement, CAT021 ADS-B, CAT034 radar
//! service messages, CAT048 monoradar, CAT062 system tracks).
//!
//! All the moving parts — config, key, mTLS NATS, the transport, the
//! seal-and-publish loop, health, shutdown — live in `ajar_connector_common`.
//! This binary is only the wiring: read config, build the ASTERIX parser (with the
//! optional radar site for CAT048/CAT010 geolocation and the operator's entity
//! choices), open the transport, run.

use ajar_asterix::{AsterixParser, Sensor};
use ajar_connector_common::{open_source, run, Config};
use anyhow::Context;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,async_nats=warn".into()),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    // The first non-flag argument is the config path, so `--profile` may sit on
    // either side of it.
    let path = args
        .iter()
        .skip(1)
        .find(|a| !a.starts_with("--"))
        .cloned()
        .unwrap_or_else(|| "asterix.toml".to_string());
    let cfg = Config::load(&path).with_context(|| format!("loading {path}"))?;

    // `--profile` prints the document the operator registers and exits,
    // before any transport is opened.
    if ajar_connector_common::profile::requested(&args) {
        println!("{}", ajar_connector_common::profile::emit(&cfg, &["mim:"])?);
        return Ok(());
    }

    let sensor = cfg.sensor.map(|s| Sensor {
        lat: s.lat,
        lon: s.lon,
        alt_m: s.alt_m.unwrap_or(0.0),
    });
    let parser = AsterixParser::new(cfg.source_id.clone(), cfg.enrichment())
        .with_sensor(sensor)
        .with_entity_map(&cfg.entity_map);
    let source = open_source(&cfg.transport)
        .await
        .context("opening transport")?;

    run(cfg, source, parser).await
}
