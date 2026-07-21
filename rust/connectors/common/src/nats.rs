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

    opts.connect(url).await.context("connecting to NATS")
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
    flagged || url.trim_start().to_ascii_lowercase().starts_with("tls://")
}

fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}
