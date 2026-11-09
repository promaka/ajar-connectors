// SPDX-License-Identifier: Apache-2.0
//! Producer mode: place the credentials, write the connector config from the
//! manifest, run the doctor preflight, then exec the named connector.

use std::path::PathBuf;

use anyhow::Context;

use crate::packet::Packet;

pub struct Options {
    /// Copied to the manifest's signing_key_path (vendor-holds-key flow).
    pub signing_key: Option<PathBuf>,
    /// Print the run command instead of executing it.
    pub no_exec: bool,
    pub timeout_secs: u64,
}

pub async fn run(packet: &Packet, opts: &Options) -> anyhow::Result<()> {
    let m = &packet.manifest;
    let protocol = m.protocol.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "this producer packet names no protocol, so no connector can be chosen. \
             Ask the operator to re-issue it with --protocol (one of: tak-cot, \
             ais-nmea, asterix, mavlink, adsb, generic, klv, gmti, stanag4586, \
             stanag4676, sapient)"
        )
    })?;
    let transport = m.transport.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "this producer packet carries no transport block; ask the operator to re-issue it"
        )
    })?;

    // The seed is the flag's file, else whatever is already at the manifest's
    // path (placed by hand, or carried in the tar by the mint flow).
    let seed_rel = m.keys.signing_key_path.as_deref().ok_or_else(|| {
        anyhow::anyhow!("this producer packet names no signing_key_path in keys{{}}")
    })?;
    let seed_path = packet.path(seed_rel);
    if let Some(src) = &opts.signing_key {
        std::fs::copy(src, &seed_path)
            .with_context(|| format!("placing the signing seed at {}", seed_path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&seed_path, std::fs::Permissions::from_mode(0o600))?;
        }
    }
    if !seed_path.exists() {
        anyhow::bail!(
            "no signing seed: pass --signing-key <path>, or place your registered seed \
             at {} first. This is the key whose public half your operator registered; \
             only a packet minted with --mint carries it inside.",
            seed_path.display()
        );
    }

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
    // The config's paths are absolute only if the unpack directory is.
    cfg.insert(
        "signing_key_path".into(),
        seed_path.to_str().unwrap().into(),
    );
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

    let tls_env = mtls_env(packet);
    for (k, v) in &tls_env {
        std::env::set_var(k, v);
    }

    println!(
        "packet verified; credentials placed; config written: {}",
        config_path.display()
    );

    let findings = ajar_doctor::run(&ajar_doctor::Options {
        role: ajar_doctor::Role::Producer,
        config_path: Some(config_path.to_str().unwrap().to_string()),
        sources_dir: None,
        tls_files: None,
        timeout: std::time::Duration::from_secs(opts.timeout_secs),
    })
    .await;
    let (report, healthy) = ajar_doctor::report::render(&findings);
    print!("{report}");
    if !healthy {
        anyhow::bail!("the preflight failed; fix the first FAIL above and run ajar-up again");
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
        // exec, so the connector is the process the operator sees in ps and
        // receives its signals.
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

/// The AJAR_TLS_* triple from the packet's key paths, when all three exist.
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

/// The connector binary beside ajar-up (the tarball layout), else on PATH.
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
    anyhow::bail!(
        "{name} is not beside ajar-up or on PATH. Download the {name} release for \
         your platform and unpack it next to ajar-up, or put {name} on PATH."
    )
}
