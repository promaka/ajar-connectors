// SPDX-License-Identifier: Apache-2.0
//! ASTERIX ingress connector (CAT021 ADS-B, CAT048 monoradar, CAT062 system tracks).
//!
//! All the moving parts — config, key, mTLS NATS, the transport, the
//! seal-and-publish loop, health, shutdown — live in `ajar_connector_common`.
//! This binary is only the wiring: read config, build the ASTERIX parser (with the
//! optional radar site for CAT048 geolocation), open the transport, run.

use ajar_asterix::{AsterixParser, Sensor};
use ajar_connector_common::{open_source, run, Config};
use anyhow::Context;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "asterix.toml".to_string());
    let cfg = Config::load(&path).with_context(|| format!("loading {path}"))?;

    let sensor = cfg.sensor.map(|s| Sensor {
        lat: s.lat,
        lon: s.lon,
    });
    let parser = AsterixParser::new(cfg.source_id.clone(), cfg.enrichment()).with_sensor(sensor);
    let source = open_source(&cfg.transport)
        .await
        .context("opening transport")?;

    run(cfg, source, parser).await
}
