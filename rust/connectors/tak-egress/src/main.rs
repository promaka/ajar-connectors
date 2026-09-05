// SPDX-License-Identifier: Apache-2.0
//! TAK info-egress relay binary. All logic lives in the library (`run`); this is
//! only config + tracing wiring, matching the ingress connectors' shape.

use ajar_tak_egress::EgressConfig;
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
        .unwrap_or_else(|| "tak-egress.toml".to_string());
    let cfg = EgressConfig::load(&path).with_context(|| format!("loading {path}"))?;

    ajar_tak_egress::run(cfg).await
}
