// SPDX-License-Identifier: Apache-2.0
//! Governed egress by field mapping. See lib.rs for the pipeline; this binary
//! is the wiring: config, NATS subscription, delivery loop, health.
//!
//! There is no way to deliver an unverified payload. Verification has no off
//! switch, the egress key is required config, and `--dry-run` (print instead of
//! POST) verifies exactly the same way — the one relaxation is that dry-run
//! without a configured key prints payload SIZES under an UNVERIFIED banner,
//! never content mapped as if it were governed.

use std::sync::atomic::Ordering;

use ajar_generic_egress::{accept, config::Config, map, Dedupe, EgressMetrics, DEDUPE_WINDOW};
use anyhow::Context;
use futures_util::StreamExt;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    let dry_run = args.iter().any(|a| a == "--dry-run");
    let path = args
        .iter()
        .skip(1)
        .find(|a| !a.starts_with("--"))
        .cloned()
        .unwrap_or_else(|| "generic-egress.toml".to_string());
    let cfg = Config::load(&path).with_context(|| format!("loading {path}"))?;

    let key = match cfg.verifying_key() {
        Ok(k) => Some(k),
        Err(e) if dry_run => {
            tracing::warn!("UNVERIFIED dry-run: {e}; payload sizes only, no content");
            None
        }
        Err(e) => return Err(e),
    };

    let metrics = EgressMetrics::default();
    let client = ajar_connector_common::nats::connect(&cfg.nats_url).await?;
    let mut sub = client.subscribe(cfg.subject.clone()).await?;
    tracing::info!(
        subject = %cfg.subject,
        deliver = %cfg.deliver.url,
        dry_run,
        "egress ready"
    );

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    let mut dedupe = Dedupe::new(DEDUPE_WINDOW);
    let (mut received, mut heartbeat) = (
        0u64,
        tokio::time::interval(std::time::Duration::from_secs(15)),
    );

    loop {
        tokio::select! {
            message = sub.next() => {
                let Some(message) = message else {
                    tracing::warn!("subscription ended");
                    break;
                };
                received += 1;

                let Some(key) = &key else {
                    // Reachable only under --dry-run with no key configured.
                    println!("UNVERIFIED payload: {} bytes on {}", message.payload.len(), message.subject);
                    continue;
                };
                let event = match accept(&message.payload, key) {
                    Ok(event) => event,
                    Err(e) => {
                        metrics.rejected.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(error = %e, "egress envelope refused");
                        continue;
                    }
                };
                if !dedupe.first_time(&event.id) {
                    metrics.deduped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let Some(body) = map::render(
                    &event,
                    &cfg.mapping.fields,
                    cfg.unmapped,
                    cfg.confidentiality_label.as_ref(),
                ) else {
                    metrics.gap_dropped.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(id = %event.id, "event carries unmapped content and unmapped = \"refuse\"");
                    continue;
                };

                if dry_run {
                    println!("{body}");
                    metrics.delivered.fetch_add(1, Ordering::Relaxed);
                    continue;
                }

                // Bounded attempts with a short backoff; both outcomes counted.
                let mut delivered = false;
                for attempt in 0..cfg.deliver.attempts {
                    let mut req = http.post(&cfg.deliver.url).json(&body);
                    for (k, v) in &cfg.deliver.headers {
                        req = req.header(k, v);
                    }
                    match req.send().await {
                        Ok(resp) if resp.status().is_success() => {
                            delivered = true;
                            break;
                        }
                        Ok(resp) => tracing::warn!(status = %resp.status(), attempt, "consumer refused"),
                        Err(e) => tracing::warn!(error = %e, attempt, "delivery failed"),
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(500 * (attempt as u64 + 1))).await;
                }
                if delivered {
                    metrics.delivered.fetch_add(1, Ordering::Relaxed);
                } else {
                    metrics.gap_dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
            _ = heartbeat.tick() => {
                tracing::info!(
                    received,
                    delivered = metrics.delivered.load(Ordering::Relaxed),
                    rejected = metrics.rejected.load(Ordering::Relaxed),
                    deduped = metrics.deduped.load(Ordering::Relaxed),
                    gap_dropped = metrics.gap_dropped.load(Ordering::Relaxed),
                    "heartbeat"
                );
            }
        }
    }
    Ok(())
}
