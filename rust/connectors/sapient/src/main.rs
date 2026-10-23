// SPDX-License-Identifier: Apache-2.0
//! SAPIENT (BSI Flex 335) ingress connector.
//!
//! All the moving parts — config, key, mTLS NATS, the seal-and-publish loop,
//! health, shutdown — live in `ajar_connector_common`. This binary is only the
//! wiring: read config, build the parser, open the right source for the role,
//! run. In the `dmm` role the source is this crate's own acceptor, because a
//! fusion node has to answer each sensor's registration.

use ajar_connector_common::{open_source, run, Config, FrameSource, Framing, Transport};
use ajar_sapient::dmm::DmmSource;
use ajar_sapient::{Options, Role, SapientParser};
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
        .unwrap_or_else(|| "sapient.toml".to_string());
    let cfg = Config::load(&path).with_context(|| format!("loading {path}"))?;

    // `--profile` prints the document the operator registers and exits,
    // before any transport is opened.
    if ajar_connector_common::profile::requested(&args) {
        println!(
            "{}",
            ajar_connector_common::profile::emit(&cfg, &["sapient:", "mim:"])?
        );
        return Ok(());
    }

    let options = Options::from_table(&cfg.options).context("reading [options]")?;
    let mut parser = SapientParser::new(cfg.source_id.clone(), cfg.enrichment())
        .with_types(options.types.clone())
        .with_entity_map(&cfg.entity_map)
        .context("validating [entity_map]")?;

    let source: Box<dyn FrameSource> = match options.role {
        Role::Dmm => match &cfg.transport {
            Transport::TcpServer { bind, .. } => {
                let dmm = DmmSource::bind(bind, options.node_id.clone())
                    .await
                    .context("opening the fusion-node acceptor")?;
                tracing::info!(bind = %bind, node_id = %options.node_id, "accepting sapient edge nodes");
                parser = parser.with_dmm_counters(dmm.counters());
                Box::new(dmm)
            }
            other => anyhow::bail!(
                "the dmm role accepts edge nodes over TCP, so [transport] must be \
                 kind = \"tcp-server\"; it is {other:?}. For a fusion node's \
                 output or a capture, set role = \"subscriber\""
            ),
        },
        Role::Subscriber => {
            warn_if_not_the_standard_framing(&cfg.transport);
            open_source(&cfg.transport)
                .await
                .context("opening transport")?
        }
    };

    run(cfg, source, parser).await
}

/// A stream transport without the standard's framing would hand the parser
/// half-messages; say so at start-up rather than per frame.
fn warn_if_not_the_standard_framing(transport: &Transport) {
    let framing = match transport {
        Transport::TcpClient { framing, .. }
        | Transport::TcpServer { framing, .. }
        | Transport::File { framing, .. }
        | Transport::Stdin { framing } => Some(*framing),
        _ => None,
    };
    if let Some(f) = framing {
        if f != Framing::LengthU32le {
            tracing::warn!(
                framing = ?f,
                "SAPIENT messages carry a 4-byte little-endian length prefix; set framing = \"length-u32le\""
            );
        }
    }
}
