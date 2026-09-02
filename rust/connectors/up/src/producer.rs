// SPDX-License-Identifier: Apache-2.0
//! Producer mode: packet -> credentials placed -> config written -> doctor
//! preflight -> the right connector running. Zero questions, because every
//! decision travels in the manifest.

use std::path::PathBuf;

use anyhow::{anyhow, bail, Context};

use crate::packet::Packet;

pub struct Options {
    /// The vendor-holds-key flow: place this seed at the manifest's path.
    pub signing_key: Option<PathBuf>,
    /// Verify, place, configure and preflight, then PRINT the run command
    /// instead of executing it (air-gapped prep, service files, tests).
    pub no_exec: bool,
    pub timeout_secs: u64,
}

pub async fn run(packet: &Packet, opts: &Options) -> anyhow::Result<()> {
    let m = &packet.manifest;
    let protocol = m.protocol.as_deref().ok_or_else(|| {
        anyhow!(
            "this producer packet names no protocol, so no connector can be chosen. \
             Ask the operator to re-issue it with --protocol (one of: tak-cot, \
             ais-nmea, asterix, mavlink, adsb, generic, klv, gmti, stanag4586, \
             stanag4676)"
        )
    })?;
    let transport = m.transport.as_ref().ok_or_else(|| {
        anyhow!("this producer packet carries no transport block; ask the operator to re-issue it")
    })?;

    // The signing seed, by the agreed precedence: the flag, the file already
    // at the manifest's path, or the seed the tar itself carried (mint flow).
    let seed_rel = m
        .keys
        .signing_key_path
        .as_deref()
        .ok_or_else(|| anyhow!("this producer packet names no signing_key_path in keys{{}}"))?;
    let seed_abs = packet.path(seed_rel);
    if let Some(src) = &opts.signing_key {
        std::fs::copy(src, &seed_abs)
            .with_context(|| format!("placing the signing seed at {}", seed_abs.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&seed_abs, std::fs::Permissions::from_mode(0o600))?;
        }
    }
    if !seed_abs.exists() {
        bail!(
            "no signing seed: pass --signing-key <path>, or place your registered seed \
             at {} first. This is the key whose public half your operator registered; \
             only a packet minted with --mint carries it inside.",
            seed_abs.display()
        );
    }

    // The connector config, synthesized from the manifest. Absolute paths
    // throughout, so the connector runs from anywhere.
    let subject_prefix = match &m.subject {
        Some(s) => s
            .strip_suffix(&format!(".{}", m.source_id))
            .unwrap_or("ajar.ingest")
            .to_string(),
        None => "ajar.ingest".to_string(),
    };
    let mut cfg = toml::Table::new();
    cfg.insert("source_id".into(), m.source_id.clone().into());
    cfg.insert("nats_url".into(), m.nats_url.clone().into());
    cfg.insert("subject_prefix".into(), subject_prefix.into());
    cfg.insert("signing_key_path".into(), seed_abs.to_str().unwrap().into());
    let transport_toml: toml::Value = serde_json::from_value::<toml::Value>(transport.clone())
        .context("the manifest's transport block does not convert to config TOML")?;
    cfg.insert("transport".into(), transport_toml);
    if let Some(spool) = &m.spool {
        cfg.insert(
            "spool".into(),
            serde_json::from_value::<toml::Value>(spool.clone())
                .context("the manifest's spool setting does not convert to config TOML")?,
        );
    }
    let config_path = packet.path(&format!("{}.toml", m.source_id));
    std::fs::write(&config_path, toml::to_string_pretty(&cfg)?)
        .with_context(|| format!("writing {}", config_path.display()))?;

    // mTLS environment, when the packet carries the triple.
    let tls_env = mtls_env(packet);
    for (k, v) in &tls_env {
        std::env::set_var(k, v);
    }

    println!(
        "packet verified; credentials placed; config written: {}",
        config_path.display()
    );

    // The doctor is the trust moment: the same preflight a human would run,
    // run for them, against the exact config the connector will use.
    let findings = ajar_doctor::run(&ajar_doctor::Options {
        config_path: Some(config_path.to_str().unwrap().to_string()),
        sources_dir: None,
        timeout: std::time::Duration::from_secs(opts.timeout_secs),
    })
    .await;
    let (report, healthy) = ajar_doctor::report::render(&findings);
    print!("{report}");
    if !healthy {
        bail!("the preflight failed; fix the first FAIL above and run ajar-up again");
    }

    let binary = locate_binary(&format!("ajar-{protocol}"))?;
    let run_line = format!("{} {}", binary.display(), config_path.display());
    if opts.no_exec {
        println!("ready to run:");
        for (k, v) in &tls_env {
            println!("  export {k}={v}");
        }
        println!("  {run_line}");
        return Ok(());
    }

    println!("starting: {run_line}");
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // exec replaces this process: the connector IS the command the
        // operator sees in ps, signals land where they should, and ajar-up
        // leaves nothing running behind it.
        Err(std::process::Command::new(&binary)
            .arg(&config_path)
            .exec()
            .into())
    }
    #[cfg(not(unix))]
    {
        let status = std::process::Command::new(&binary)
            .arg(&config_path)
            .status()?;
        std::process::exit(status.code().unwrap_or(1));
    }
}

/// The AJAR_TLS_* triple from the packet's key paths, when all present.
pub fn mtls_env(packet: &Packet) -> Vec<(&'static str, String)> {
    let k = &packet.manifest.keys;
    match (&k.ca_cert_path, &k.mtls_cert_path, &k.mtls_key_path) {
        (Some(ca), Some(cert), Some(key))
            if packet.path(ca).exists()
                && packet.path(cert).exists()
                && packet.path(key).exists() =>
        {
            vec![
                ("AJAR_TLS_CA", packet.path(ca).to_str().unwrap().to_string()),
                (
                    "AJAR_TLS_CERT",
                    packet.path(cert).to_str().unwrap().to_string(),
                ),
                (
                    "AJAR_TLS_KEY",
                    packet.path(key).to_str().unwrap().to_string(),
                ),
            ]
        }
        _ => Vec::new(),
    }
}

/// Find the connector binary: beside ajar-up first (the tarball layout),
/// then PATH.
fn locate_binary(name: &str) -> anyhow::Result<PathBuf> {
    if let Ok(me) = std::env::current_exe() {
        if let Some(dir) = me.parent() {
            let candidate = dir.join(name);
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }
    if let Ok(path) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join(name);
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }
    bail!(
        "{name} is not beside ajar-up or on PATH. The release tarball carries every \
         connector next to ajar-up; run from the unpacked tarball, or install the \
         connectors on PATH."
    )
}
