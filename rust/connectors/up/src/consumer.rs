// SPDX-License-Identifier: Apache-2.0
//! Consumer mode: subscribe to governed egress, verify every event under the
//! deployment's egress key, and write each accepted payload to stdout, one per
//! line; what does not verify is counted and dropped. `--to-tak`/`--to-http`
//! write a ready egress-connector config for a real delivery target instead.

use anyhow::Context;
use ed25519_dalek::VerifyingKey;
use futures_util::StreamExt as _;
use prost::Message as _;
use tokio::io::AsyncWriteExt as _;

use crate::packet::{Manifest, Packet};

/// Everything `run` checks before touching the network: subject, egress key,
/// formats and referenced cert files. `packet::open` already verified the
/// signature and checksums.
pub fn check(packet: &Packet) -> anyhow::Result<()> {
    let m = &packet.manifest;
    let (subject, _) = egress(m)?;
    for path in [
        m.keys.ca_cert_path.as_deref(),
        m.keys.mtls_cert_path.as_deref(),
        m.keys.mtls_key_path.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if !packet.path(path).exists() {
            anyhow::bail!("the manifest references {path} but the packet did not deliver it");
        }
    }
    println!(
        "consumer packet valid: subscribe {} (formats: {})",
        subject,
        m.formats
            .as_deref()
            .map(|f| f.join(", "))
            .unwrap_or_else(|| "unspecified".into())
    );
    Ok(())
}

/// The egress subject and verifying key a consumer packet must carry.
fn egress(m: &Manifest) -> anyhow::Result<(&str, VerifyingKey)> {
    let subject = m.egress_subject.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "this consumer packet names no egress_subject; ask the operator to re-issue it"
        )
    })?;
    let key_hex = m.egress_verifying_key_hex.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "this consumer packet carries no egress_verifying_key_hex, so received \
             events could not be verified; ask the operator to re-issue it"
        )
    })?;
    let key_bytes: [u8; 32] = hex::decode(key_hex.trim())
        .context("egress_verifying_key_hex is not hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("egress_verifying_key_hex must be 32 bytes"))?;
    let key = VerifyingKey::from_bytes(&key_bytes).context("egress verifying key is invalid")?;
    Ok((subject, key))
}

pub struct Options {
    pub to_tak: Option<String>,
    pub to_http: Option<String>,
}

pub async fn run(packet: &Packet, opts: &Options) -> anyhow::Result<()> {
    let m = &packet.manifest;
    let (subject, egress_key) = egress(m)?;
    let formats: Vec<String> = m.formats.clone().unwrap_or_default();

    // A delivery flag must name a format the deployment egresses.
    if let Some(tak) = &opts.to_tak {
        if !formats.iter().any(|f| f == "cot") {
            return Err(format_error(&formats, "cot", "--to-tak"));
        }
        return write_tak_config(packet, tak);
    }
    if let Some(url) = &opts.to_http {
        let format = ["geojson", "json"]
            .iter()
            .find(|f| formats.iter().any(|have| have == *f))
            .ok_or_else(|| format_error(&formats, "geojson/json", "--to-http"))?;
        return write_http_config(packet, url, format);
    }

    for (k, v) in crate::producer::mtls_env(packet) {
        std::env::set_var(k, v);
    }
    let client = ajar_connector_common::nats::connect(&m.nats_url)
        .await
        .context("connecting to the egress endpoint")?;
    let mut sub = client
        .subscribe(subject.to_string())
        .await
        .with_context(|| format!("subscribing to {subject}"))?;
    eprintln!(
        "[ajar-up] verified tap: {} (formats: {}) - accepted payloads to stdout, \
         one per line; anything that fails verification is dropped and counted",
        subject,
        if formats.is_empty() {
            "unspecified".into()
        } else {
            formats.join(", ")
        }
    );

    let mut accepted: u64 = 0;
    let mut rejected: u64 = 0;
    let mut stdout = tokio::io::stdout();
    while let Some(msg) = sub.next().await {
        match ajar_connector::verify(&msg.payload, &egress_key) {
            Ok(canonical) => match ajar_connector::Event::decode(canonical) {
                Ok(event) => {
                    accepted += 1;
                    stdout.write_all(&event.payload).await?;
                    stdout.write_all(b"\n").await?;
                    stdout.flush().await?;
                }
                Err(e) => {
                    rejected += 1;
                    eprintln!("[ajar-up] rejected (verified bytes are not an event: {e}); total rejected {rejected}");
                }
            },
            Err(_) => {
                rejected += 1;
                eprintln!(
                    "[ajar-up] rejected (does not verify under the egress key); \
                     total rejected {rejected}, accepted {accepted}"
                );
            }
        }
    }
    Ok(())
}

fn format_error(formats: &[String], want: &str, flag: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "{flag} needs the {want} format, but this packet's deployment egresses: {}. \
         Ask the operator to enable it, or consume one of the listed formats.",
        if formats.is_empty() {
            "(none listed)".into()
        } else {
            formats.join(", ")
        }
    )
}

/// A tak-egress config on the CoT egress slug. The TAK-side client
/// certificate is issued by the TAK Server's owner, so those two lines are
/// left to fill.
fn write_tak_config(packet: &Packet, tak_url: &str) -> anyhow::Result<()> {
    let m = &packet.manifest;
    let path = packet.path(&format!("{}-tak-egress.toml", m.source_id));
    let ca = m.keys.ca_cert_path.as_deref().unwrap_or("ca.crt");
    let text = format!(
        "nats_url = \"{}\"\n\
         # The CoT egress slug: only rendered CoT, not every format.\n\
         egress_subject = \"ajar.egress.cot.>\"\n\
         # Not read: the CoT channel is not signed.\n\
         egress_verifying_key = \"{}\"\n\
         target = \"{}\"\n\n\
         [tak]\n\
         # Enrolled with YOUR TAK Server (its owner issues these two):\n\
         tls_cert = \"FILL-ME.client.pem\"\n\
         tls_key = \"FILL-ME.client.key\"\n\
         # CA that signed the TAK Server's certificate (often your own PKI's):\n\
         tls_ca = \"{}\"\n",
        m.nats_url,
        packet.path("egress.pub").display(),
        tak_url,
        packet.path(ca).display(),
    );
    std::fs::write(&path, text).with_context(|| format!("writing {}", path.display()))?;
    println!(
        "wrote {}\nfill the two TAK-enrolled TLS lines, then run:\n  ajar-tak-egress {}",
        path.display(),
        path.display()
    );
    Ok(())
}

/// A generic-egress config delivering the JSON rendering to a webhook.
fn write_http_config(packet: &Packet, url: &str, format: &str) -> anyhow::Result<()> {
    let m = &packet.manifest;
    let path = packet.path(&format!("{}-http-egress.toml", m.source_id));
    let text = format!(
        "nats_url = \"{}\"\n\
         egress_subject = \"ajar.egress.{format}.>\"\n\
         egress_verifying_key = \"{}\"\n\
         target = \"{}\"\n\
         unmapped = \"include\"\n\n\
         # Consumer-shaped field names go here; unmapped governed content is\n\
         # delivered under `unmapped` either way (markings cannot be mapped away).\n\
         [mapping]\n",
        m.nats_url,
        packet.path("egress.pub").display(),
        url,
    );
    std::fs::write(&path, text).with_context(|| format!("writing {}", path.display()))?;
    println!(
        "wrote {}\nrun it with:\n  ajar-generic-egress {}",
        path.display(),
        path.display()
    );
    Ok(())
}
