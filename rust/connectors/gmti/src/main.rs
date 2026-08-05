// SPDX-License-Identifier: Apache-2.0
//! STANAG 4607 (NATO GMTI) ingress connector.
//!
//! All the moving parts — config, key, mTLS NATS, the transport, the
//! seal-and-publish loop, health, shutdown — live in `ajar_connector_common`.
//! This binary is only the wiring: read config, build the GMTI parser, open the
//! transport, run.

use ajar_connector_common::{open_source, run, Config};
use ajar_gmti::GmtiParser;
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
        .unwrap_or_else(|| "gmti.toml".to_string());
    let cfg = Config::load(&path).with_context(|| format!("loading {path}"))?;

    let parser = GmtiParser::new(cfg.source_id.clone(), cfg.enrichment());
    let source = open_source(&cfg.transport)
        .await
        .context("opening transport")?;

    run(cfg, source, parser).await
}
