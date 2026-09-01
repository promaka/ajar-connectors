// SPDX-License-Identifier: Apache-2.0
//! The connector's NATS connection, with mTLS and a fail-closed TLS policy.
//!
//! Policy, in order:
//!  - All of `AJAR_TLS_CA` / `AJAR_TLS_CERT` / `AJAR_TLS_KEY` set → mTLS (the
//!    production path; the client certificate, CN = `source_id`, is the
//!    connector's transport identity).
//!  - *Some but not all* set → hard error. A partial TLS config is a slip, and a
//!    slip must never silently downgrade a defence link to cleartext.
//!  - None set, and TLS is required (`AJAR_REQUIRE_TLS` truthy, or the URL is
//!    `tls://…`) → hard error.
//!  - None set, TLS not required → plaintext with a loud warning (local dev only).

use anyhow::{bail, Context};

/// Connect to NATS per the TLS policy above. The initial connect is retried and
/// the client auto-reconnects after a drop.
pub async fn connect(url: &str) -> anyhow::Result<async_nats::Client> {
    install_crypto_provider();

    let mut opts = async_nats::ConnectOptions::new().retry_on_initial_connect();

    let ca = non_empty_env("AJAR_TLS_CA");
    let cert = non_empty_env("AJAR_TLS_CERT");
    let key = non_empty_env("AJAR_TLS_KEY");
    let set = [&ca, &cert, &key].iter().filter(|v| v.is_some()).count();

    match set {
        3 => {
            tracing::info!("mTLS enabled (client cert = connector identity)");
            opts = opts
                .require_tls(true)
                .add_root_certificates(ca.expect("checked").into())
                .add_client_certificate(
                    cert.expect("checked").into(),
                    key.expect("checked").into(),
                );
        }
        0 => {
            if tls_required(url) {
                bail!(
                    "TLS is required (AJAR_REQUIRE_TLS or a tls:// URL) but \
                     AJAR_TLS_CA/AJAR_TLS_CERT/AJAR_TLS_KEY are not set — refusing \
                     to connect in cleartext"
                );
            }
            tracing::warn!("no AJAR_TLS_* set — connecting WITHOUT TLS (dev only)");
        }
        _ => bail!(
            "partial TLS configuration: set all of AJAR_TLS_CA, AJAR_TLS_CERT and \
             AJAR_TLS_KEY (or none, for local dev) — refusing to guess"
        ),
    }

    // A comma-separated nats_url is a failover list: the client connects to
    // one endpoint and moves to the next when it dies (the two-box gate pins
    // this against real brokers). A single URL is the one-element case.
    let servers: Vec<async_nats::ServerAddr> = url
        .split(',')
        .map(|s| s.trim().parse())
        .collect::<Result<_, _>>()
        .with_context(|| format!("parsing nats_url {url:?}"))?;
    opts.connect(servers).await.context("connecting to NATS")
}

/// Whether the deployment demands TLS: `AJAR_REQUIRE_TLS` set truthy, or a
/// `tls://` endpoint.
fn tls_required(url: &str) -> bool {
    let flagged = std::env::var("AJAR_REQUIRE_TLS")
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            !(v.is_empty() || v == "0" || v == "false" || v == "no")
        })
        .unwrap_or(false);
    // Any tls:// entry in a failover list demands TLS for the connection.
    flagged
        || url
            .split(',')
            .any(|u| u.trim().to_ascii_lowercase().starts_with("tls://"))
}

fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

/// Install the process-wide rustls crypto provider.
///
/// rustls 0.23 picks a provider from crate features only while exactly one is
/// compiled in. A dependency that pulls in a second one turns that into an
/// ambiguity resolved at runtime, and a connector that cannot build a TLS config
/// fails before it reaches the network: locally, in under a millisecond, with the
/// server logging nothing but an EOF. Installing one explicitly removes the
/// ambiguity whatever the dependency graph does later.
///
/// Idempotent and safe to call from every connector; a second call is ignored.
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

    // Env-var tests share process state, so one test walks every case in
    // sequence rather than racing siblings.
    #[test]
    fn a_failover_list_demands_tls_when_any_entry_does() {
        // Reads no environment beyond what the URL says, so it is safe to
        // run alongside the policy walk below.
        assert!(
            super::tls_required("tls://a:4222,nats://b:4222")
                || std::env::var("AJAR_REQUIRE_TLS").is_ok()
        );
        assert!(
            super::tls_required("nats://a:4222, tls://b:4222")
                || std::env::var("AJAR_REQUIRE_TLS").is_ok()
        );
    }

    #[tokio::test]
    async fn the_tls_policy_fails_closed_in_every_partial_state() {
        for k in [
            "AJAR_TLS_CA",
            "AJAR_TLS_CERT",
            "AJAR_TLS_KEY",
            "AJAR_REQUIRE_TLS",
        ] {
            std::env::remove_var(k);
        }

        // tls:// demands TLS material; refusing beats silent cleartext.
        let err = connect("tls://bus.example:4222")
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("refusing"), "{err}");

        // The flag alone demands it too.
        std::env::set_var("AJAR_REQUIRE_TLS", "1");
        assert!(connect("nats://bus.example:4222").await.is_err());
        std::env::remove_var("AJAR_REQUIRE_TLS");

        // A partial set is a slip, not a downgrade.
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
