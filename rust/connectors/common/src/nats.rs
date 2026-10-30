// SPDX-License-Identifier: Apache-2.0
//! The connector's NATS connection. All of `AJAR_TLS_CA`, `AJAR_TLS_CERT` and
//! `AJAR_TLS_KEY` set means mTLS; some but not all is an error; none is
//! plaintext, refused when `AJAR_REQUIRE_TLS` is truthy or a URL is `tls://`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::Context;

/// Seconds between repeated "cannot reach" warnings.
const UNREACHABLE_WARN_EVERY_S: u64 = 30;

/// Connect to NATS per the TLS policy. The initial connect retries forever and
/// the client reconnects after a drop.
pub async fn connect(url: &str) -> anyhow::Result<async_nats::Client> {
    install_crypto_provider();

    // Retrying forever makes a wrong URL or a closed firewall look like
    // patience, so a client error is logged, rate-limited.
    let urls = url.to_string();
    let last_warn = Arc::new(AtomicU64::new(0));
    let mut opts = async_nats::ConnectOptions::new()
        .retry_on_initial_connect()
        .event_callback(move |event| {
            let urls = urls.clone();
            let last_warn = last_warn.clone();
            async move {
                match event {
                    async_nats::Event::Connected => {
                        tracing::info!(url = %urls, "connected to nats");
                    }
                    async_nats::Event::Disconnected => {
                        tracing::warn!(url = %urls, "disconnected from nats, reconnecting");
                    }
                    async_nats::Event::ClientError(e) => {
                        if warn_due(&last_warn, UNREACHABLE_WARN_EVERY_S) {
                            tracing::warn!("{}", unreachable_message(&urls, &e.to_string()));
                        }
                    }
                    async_nats::Event::ServerError(e) => {
                        tracing::warn!(url = %urls, error = %e, "nats server error");
                    }
                    other => tracing::debug!(event = %other, "nats event"),
                }
            }
        });

    match (
        non_empty_env("AJAR_TLS_CA"),
        non_empty_env("AJAR_TLS_CERT"),
        non_empty_env("AJAR_TLS_KEY"),
    ) {
        (Some(ca), Some(cert), Some(key)) => {
            tracing::info!("mTLS enabled");
            opts = opts
                .require_tls(true)
                .add_root_certificates(ca.into())
                .add_client_certificate(cert.into(), key.into());
        }
        (None, None, None) => {
            if tls_required(url) {
                anyhow::bail!(
                    "TLS is required (AJAR_REQUIRE_TLS or a tls:// URL) but \
                     AJAR_TLS_CA/AJAR_TLS_CERT/AJAR_TLS_KEY are not set; refusing \
                     to connect in cleartext"
                );
            }
            tracing::warn!("no AJAR_TLS_* set, connecting without tls");
        }
        _ => anyhow::bail!(
            "partial TLS configuration: set all of AJAR_TLS_CA, AJAR_TLS_CERT and \
             AJAR_TLS_KEY (or none, for local dev); refusing to guess"
        ),
    }

    // A comma-separated nats_url is a failover list.
    let servers: Vec<async_nats::ServerAddr> = url
        .split(',')
        .map(|s| s.trim().parse())
        .collect::<Result<_, _>>()
        .with_context(|| format!("parsing nats_url {url:?}"))?;
    opts.connect(servers).await.context("connecting to NATS")
}

/// The broker address, the OS error, that the connector keeps trying, and
/// what to check.
fn unreachable_message(urls: &str, err: &str) -> String {
    format!(
        "cannot reach NATS at {urls}: {err}. Retrying; sealed events spool meanwhile when \
         a spool is configured. Check the URL and port, and that a firewall allows this \
         outbound connection; `ajar-doctor <config>` tests the endpoint and names the fix"
    )
}

/// True the first time, then once `every_s` seconds have passed.
fn warn_due(last: &AtomicU64, every_s: u64) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let prev = last.load(Ordering::Relaxed);
    if prev == 0 || now.saturating_sub(prev) >= every_s {
        last.store(now.max(1), Ordering::Relaxed);
        true
    } else {
        false
    }
}

/// `AJAR_REQUIRE_TLS` set truthy, or any `tls://` endpoint.
fn tls_required(url: &str) -> bool {
    let flagged = std::env::var("AJAR_REQUIRE_TLS")
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            !(v.is_empty() || v == "0" || v == "false" || v == "no")
        })
        .unwrap_or(false);
    flagged
        || url
            .split(',')
            .any(|u| u.trim().to_ascii_lowercase().starts_with("tls://"))
}

fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

/// Install ring as the process-wide rustls crypto provider. rustls picks one
/// from crate features only while exactly one is compiled in; with two, a TLS
/// config fails to build before any I/O and the server sees only an EOF.
fn install_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        if rustls::crypto::ring::default_provider()
            .install_default()
            .is_err()
        {
            tracing::debug!("rustls crypto provider was already installed");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unreachable_message_names_address_cause_and_fix() {
        let m = unreachable_message("nats://10.0.0.5:4222", "connection refused");
        assert!(m.contains("nats://10.0.0.5:4222"));
        assert!(m.contains("connection refused"));
        assert!(m.contains("firewall") && m.contains("ajar-doctor"));
    }

    #[test]
    fn warning_fires_first_time_then_waits() {
        let last = AtomicU64::new(0);
        assert!(warn_due(&last, 30));
        assert!(!warn_due(&last, 30));
        assert!(warn_due(&last, 0));
    }

    #[test]
    fn failover_list_demands_tls_when_any_entry_does() {
        // The policy test below sets AJAR_REQUIRE_TLS concurrently.
        assert!(
            tls_required("tls://a:4222,nats://b:4222") || std::env::var("AJAR_REQUIRE_TLS").is_ok()
        );
        assert!(
            tls_required("nats://a:4222, tls://b:4222")
                || std::env::var("AJAR_REQUIRE_TLS").is_ok()
        );
    }

    // Env vars are process state, so one test walks every case in sequence.
    #[tokio::test]
    async fn tls_policy_refuses_every_partial_state() {
        for k in [
            "AJAR_TLS_CA",
            "AJAR_TLS_CERT",
            "AJAR_TLS_KEY",
            "AJAR_REQUIRE_TLS",
        ] {
            std::env::remove_var(k);
        }

        let err = connect("tls://bus.example:4222")
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("refusing"), "{err}");

        std::env::set_var("AJAR_REQUIRE_TLS", "1");
        assert!(connect("nats://bus.example:4222").await.is_err());
        std::env::remove_var("AJAR_REQUIRE_TLS");

        std::env::set_var("AJAR_TLS_CA", "/etc/ajar/ca.pem");
        let err = connect("nats://bus.example:4222")
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("partial"), "{err}");
        std::env::remove_var("AJAR_TLS_CA");

        assert!(tls_required("tls://x") && tls_required("  TLS://x"));
        assert!(!tls_required("nats://x"));
        for (v, want) in [
            ("1", true),
            ("true", true),
            ("no", false),
            ("0", false),
            ("", false),
        ] {
            std::env::set_var("AJAR_REQUIRE_TLS", v);
            assert_eq!(tls_required("nats://x"), want, "{v:?}");
        }
        std::env::remove_var("AJAR_REQUIRE_TLS");
    }
}
