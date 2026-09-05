// SPDX-License-Identifier: Apache-2.0
//! AIS / NMEA ingress connector.
//!
//! All the moving parts — config, key, mTLS NATS, the transport, the
//! seal-and-publish loop, health, shutdown — live in `ajar_connector_common`.
//! This binary is only the wiring: read config, build the AIS parser, open the
//! transport, run.

use ajar_ais_nmea::AisParser;
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
        .unwrap_or_else(|| "ais-nmea.toml".to_string());
    let cfg = Config::load(&path).with_context(|| format!("loading {path}"))?;

    // `--profile` prints the document the operator registers and exits,
    // before any transport is opened.
    if ajar_connector_common::profile::requested(&args) {
        println!("{}", ajar_connector_common::profile::emit(&cfg, &["mim:"])?);
        return Ok(());
    }

    let mut parser = AisParser::new(cfg.source_id.clone(), cfg.enrichment());
    // A shore-mounted ARPA's fixed site geolocates its TTM targets when no GPS
    // shares the bus; afloat, the feed's own GGA/RMC fixes win.
    if let Some(site) = &cfg.sensor {
        parser = parser.with_site(site.lat, site.lon);
    }
    let source = open_source(&cfg.transport)
        .await
        .context("opening transport")?;

    run(cfg, source, parser).await
}
