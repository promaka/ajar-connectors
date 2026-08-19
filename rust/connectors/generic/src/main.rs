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

    let args: Vec<String> = std::env::args().collect();
    // The first non-flag argument is the config path, so `--profile` may sit on
    // either side of it.
    let path = args
        .iter()
        .skip(1)
        .find(|a| !a.starts_with("--"))
        .cloned()
        .unwrap_or_else(|| "generic.toml".to_string());
    let cfg = Config::load(&path).with_context(|| format!("loading {path}"))?;

    let mapping = Mapping::load(&path).with_context(|| format!("loading mapping from {path}"))?;

    // `--profile` prints the document the operator registers and exits, before
    // any transport is opened. The no-code connector emits exactly the type its
    // [mapping] declares, so that is the whole allowed set.
    if ajar_connector_common::profile::requested(&args) {
        println!(
            "{}",
            ajar_connector_common::profile::emit(&cfg, &[mapping.entity_type.as_str()])?
        );
        return Ok(());
    }

    let parser = GenericParser::new(cfg.source_id.clone(), mapping, cfg.enrichment());
    let source = open_source(&cfg.transport)
        .await
        .context("opening transport")?;

    run(cfg, source, parser).await
}
