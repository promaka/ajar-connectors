// SPDX-License-Identifier: Apache-2.0
//! AIS / NMEA ingress connector.

use ajar_ais_nmea::AisParser;
use ajar_connector_common::Config;
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
    // The config path is the first non-flag argument.
    let path = args
        .iter()
        .skip(1)
        .find(|a| !a.starts_with("--"))
        .cloned()
        .unwrap_or_else(|| "ais-nmea.toml".to_string());
    let cfg = Config::load(&path).with_context(|| format!("loading {path}"))?;

    // Print the profile the operator registers, before any transport opens.
    if ajar_connector_common::profile::requested(&args) {
        println!("{}", ajar_connector_common::profile::emit(&cfg, &["mim:"])?);
        return Ok(());
    }

    let mut parser = AisParser::new(cfg.source_id.clone(), cfg.enrichment());
    if let Some(site) = &cfg.sensor {
        parser = parser.with_site(site.lat, site.lon);
    }
    let source = ajar_connector_common::open_source(&cfg.transport)
        .await
        .context("opening transport")?;

    ajar_connector_common::run(cfg, source, parser).await
}
