// SPDX-License-Identifier: Apache-2.0
//! SAPIENT (BSI Flex 335) ingress connector. In the `dmm` role the source is
//! this crate's acceptor, since a fusion node answers each registration.

use ajar_connector_common::{Config, FrameSource, Framing, Transport};
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
    // The config path is the first non-flag argument.
    let path = args
        .iter()
        .skip(1)
        .find(|a| !a.starts_with("--"))
        .cloned()
        .unwrap_or_else(|| "sapient.toml".to_string());
    let cfg = Config::load(&path).with_context(|| format!("loading {path}"))?;

    // Print the profile the operator registers, before any transport opens.
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
                parser = parser.with_dmm_counters(dmm.counters.clone());
                Box::new(dmm)
            }
            other => anyhow::bail!(
                "role dmm needs [transport] kind = \"tcp-server\", not {other:?}; \
                 a fusion node's output or a capture takes role = \"subscriber\""
            ),
        },
        Role::Subscriber => {
            let framing = match &cfg.transport {
                Transport::TcpClient { framing, .. }
                | Transport::TcpServer { framing, .. }
                | Transport::File { framing, .. }
                | Transport::Stdin { framing } => Some(*framing),
                _ => None,
            };
            // Any other framing hands the parser half-messages.
            if let Some(f) = framing.filter(|f| *f != Framing::LengthU32le) {
                tracing::warn!(
                    framing = ?f,
                    expected = "length-u32le",
                    "framing is not the sapient length prefix"
                );
            }
            ajar_connector_common::open_source(&cfg.transport)
                .await
                .context("opening transport")?
        }
    };

    ajar_connector_common::run(cfg, source, parser).await
}
