// SPDX-License-Identifier: Apache-2.0
//! Config-driven ingress connector.
//!
//! Reads the connector config (identity, transport, key) and the `[mapping]`
//! block from the same TOML file, builds a mapping parser, and runs it on the
//! shared runtime. No source-specific code.

use ajar_connector_common::{open_source, run, Config};
use ajar_generic::{GenericParser, Mapping};
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
        .unwrap_or_else(|| "generic.toml".to_string());
    let cfg = Config::load(&path).with_context(|| format!("loading {path}"))?;
    let mapping = Mapping::load(&path).with_context(|| format!("loading mapping from {path}"))?;

    let parser = GenericParser::new(cfg.source_id.clone(), mapping, cfg.enrichment());
    let source = open_source(&cfg.transport)
        .await
        .context("opening transport")?;

    run(cfg, source, parser).await
}
