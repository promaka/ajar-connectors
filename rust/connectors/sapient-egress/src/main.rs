// SPDX-License-Identifier: Apache-2.0
//! SAPIENT (BSI Flex 335) egress connector: Ajar as a sensor node on a
//! fusion node. The wiring only; see `lib.rs`.

use ajar_sapient_egress::EgressConfig;
use anyhow::Context;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,async_nats=warn".into()),
        )
        .init();

    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "sapient-egress.toml".to_string());
    let cfg = EgressConfig::load(&path).with_context(|| format!("loading {path}"))?;

    ajar_sapient_egress::run(cfg).await
}
