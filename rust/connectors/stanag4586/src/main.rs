// SPDX-License-Identifier: Apache-2.0
//! STANAG 4586 (NATO UAS Control) ingress connector.
//!
//! All the moving parts — config, key, mTLS NATS, the transport, the
//! seal-and-publish loop, health, shutdown — live in `ajar_connector_common`.
//! This binary is only the wiring: read config, build the 4586 parser, open the
//! transport, run.

use ajar_connector_common::{open_source, run, Config};
use ajar_stanag4586::S4586Parser;
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
        .unwrap_or_else(|| "stanag4586.toml".to_string());
    let cfg = Config::load(&path).with_context(|| format!("loading {path}"))?;

    // A UAS carries no affiliation of its own; the operator asserts one (own-force
    // UAS are typically `friendly`). The entity type defaults to `mim:drone`, with
    // an optional `[entity_map] default = "..."` override.
    let parser = S4586Parser::new(cfg.source_id.clone(), cfg.enrichment())
        .with_entity_type(cfg.entity_map.get("default").cloned());
    let source = open_source(&cfg.transport)
        .await
        .context("opening transport")?;

    run(cfg, source, parser).await
}
