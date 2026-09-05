// SPDX-License-Identifier: Apache-2.0
//! `ajar-doctor`: preflight for a connector that publishes nothing.
//!
//! One command a partner runs against their own config, before or instead of a
//! support call. It walks the onboarding steps in order (config, key,
//! registration, endpoint, TLS, clock) and reports, for the first thing that is
//! broken, what to DO about it, in the words of the onboarding guide rather
//! than the words of a TLS library.
//!
//! The doctor is read-only on the wire: it dials, greets and handshakes, but
//! never publishes an event, so it is safe to point at a production endpoint.

pub mod certs;
pub mod net;
pub mod report;
pub mod tls;

use std::time::Duration;

use ajar_connector_common as common;
use report::Finding;

/// What a run needs to know.
pub struct Options {
    /// Path to the connector's own config TOML, the same file the connector
    /// runs with. `None` reads the environment instead: `NATS_URL`,
    /// `AJAR_SOURCE_ID` and `AJAR_SIGNING_SEED`, the same variables the
    /// examples and the embedding guides use, so an SDK embedder needs no
    /// file at all.
    pub config_path: Option<String>,
    /// A local sink's registered-keys directory, when the operator's sink runs
    /// on a box you can see. Enables a real registration check instead of a note.
    pub sources_dir: Option<String>,
    /// Per-network-operation deadline.
    pub timeout: Duration,
}

/// The facts every check runs against, however they were supplied.
struct Inputs {
    source_id: String,
    nats_url: String,
    signing_key_path: String,
    subject_prefix: String,
    spool: Option<common::spool::SpoolConfig>,
    transport: Option<common::Transport>,
}

/// Run every check and return the findings in onboarding order.
pub async fn run(opts: &Options) -> Vec<Finding> {
    let mut out = Vec::new();

    // Step 1: the connector's own configuration, from its config file or from
    // the environment an SDK embedder runs with.
    let resolved = match &opts.config_path {
        Some(path) => match common::Config::load(path) {
            Ok(cfg) => Ok(Inputs {
                spool: cfg.spool_config(),
                transport: Some(cfg.transport.clone()),
                source_id: cfg.source_id,
                nats_url: cfg.nats_url,
                signing_key_path: cfg.signing_key_path,
                subject_prefix: cfg.subject_prefix,
            }),
            Err(e) => Err(Finding::fail(
                "config",
                format!("{e:#}"),
                "The doctor reads the same file the connector runs with. Fix the error \
                 above; the example config shipped next to your connector (the \
                 *.example.toml in the tarball and the repo) shows every required \
                 field."
                    .to_string(),
            )),
        },
        None => inputs_from_env(),
    };
    let cfg = match resolved {
        Ok(inputs) => {
            out.push(Finding::ok(
                "config",
                format!(
                    "source {:?} publishes to {}.{} at {}",
                    inputs.source_id, inputs.subject_prefix, inputs.source_id, inputs.nats_url
                ),
            ));
            inputs
        }
        Err(finding) => {
            out.push(finding);
            for step in [
                "signing key",
                "spool",
                "registration",
                "endpoint",
                "tls policy",
                "certificate files",
                "tls handshake",
                "clock",
            ] {
                out.push(Finding::skip(step, "blocked until the config loads"));
            }
            return out;
        }
    };

    // Step 2: the signing key, via the same loader the runtime uses.
    let verifying_hex = check_signing_key(&mut out, &cfg);

    // Step 2a: the spool, when configured; a one-line hint when not.
    check_spool(&mut out, &cfg);

    // Step 2b: the native-feed transport, where a naval first hour actually
    // fails (a serial adapter that is not there, a multicast group joined on
    // the wrong network of a dual-homed box).
    check_transport(&mut out, &cfg);

    // Step 3: registration, as far as it can be seen from this box.
    check_registration(
        &mut out,
        &cfg,
        opts.sources_dir.as_deref(),
        verifying_hex.as_deref(),
    );

    // Step 4: reaching the endpoint.
    let (endpoint, greeting) = check_endpoint(&mut out, &cfg, opts.timeout).await;

    // Step 5: the TLS policy table, mirroring the runtime's fail-closed rules.
    // The demand comes from the URL itself, not from whether the endpoint
    // answered: a dead tls:// endpoint still forbids a cleartext connector.
    let url_demands_tls = net::parse_urls(&cfg.nats_url)
        .map(|eps| eps.iter().any(|e| e.tls_scheme))
        .unwrap_or(false);
    let policy = tls::policy(url_demands_tls);
    let mtls = check_policy(&mut out, &policy, greeting.as_ref());

    // Steps 6..8: certificate files, the live handshake, and the clock.
    match (mtls, endpoint) {
        (Some((ca, cert, key)), Some(ep)) => {
            let identity = check_certificate_files(&mut out, &cfg, &ca, &cert, &key);
            let server_cert =
                check_handshake(&mut out, &ep, &ca, identity, &cfg.source_id, opts.timeout).await;
            check_clock(&mut out, server_cert.as_ref());
        }
        (Some(_), None) => {
            out.push(Finding::skip(
                "certificate files",
                "blocked until the endpoint answers",
            ));
            out.push(Finding::skip(
                "tls handshake",
                "blocked until the endpoint answers",
            ));
            out.push(Finding::skip(
                "clock",
                "no TLS certificate to compare the clock against",
            ));
        }
        (None, _) => {
            out.push(Finding::skip(
                "certificate files",
                "no mTLS configured (see tls policy)",
            ));
            out.push(Finding::skip(
                "tls handshake",
                "no mTLS configured (see tls policy)",
            ));
            out.push(Finding::skip(
                "clock",
                "no TLS certificate to compare the clock against; run `date -u` and compare \
                 with a clock you trust",
            ));
        }
    }

    out
}

/// Resolve the doctor's inputs from the environment: the variables the
/// examples and embedding guides use, so a partner who built the SDK into
/// their own process (with no connector config file) can still run the
/// doctor with zero files.
fn inputs_from_env() -> Result<Inputs, Finding> {
    let get = |name: &str| std::env::var(name).ok().filter(|v| !v.trim().is_empty());
    let missing: Vec<&str> = [
        ("NATS_URL", get("NATS_URL")),
        ("AJAR_SOURCE_ID", get("AJAR_SOURCE_ID")),
        ("AJAR_SIGNING_SEED", get("AJAR_SIGNING_SEED")),
    ]
    .iter()
    .filter(|(_, v)| v.is_none())
    .map(|(n, _)| *n)
    .collect();
    if !missing.is_empty() {
        return Err(Finding::fail(
            "config",
            format!(
                "no config file given and the environment is incomplete: {} not set",
                missing.join(", ")
            ),
            "Either pass the connector's config file (ajar-doctor connector.toml) or export \
             the three variables your embedded connector runs with: NATS_URL (the operator's \
             endpoint), AJAR_SOURCE_ID (your registered source id) and AJAR_SIGNING_SEED \
             (the path to your 32-byte seed file)."
                .to_string(),
        ));
    }
    Ok(Inputs {
        source_id: get("AJAR_SOURCE_ID").expect("checked"),
        nats_url: get("NATS_URL").expect("checked"),
        signing_key_path: get("AJAR_SIGNING_SEED").expect("checked"),
        subject_prefix: "ajar.ingest".to_string(),
        spool: None,
        transport: None,
    })
}

fn check_signing_key(out: &mut Vec<Finding>, cfg: &Inputs) -> Option<String> {
    let key = match common::key::load(&cfg.signing_key_path) {
        Ok(k) => k,
        Err(e) => {
            out.push(Finding::fail(
                "signing key",
                format!("{e:#}"),
                "The seed file must be exactly 32 raw bytes or 64 hex characters. If you have \
                 an OpenSSL-generated PEM, extract the seed as shown in the onboarding guide \
                 (Keys section), or mint a fresh pair with `ajar-sink mint <source_id> <dir>` \
                 and register the new .pub with your operator."
                    .to_string(),
            ));
            return None;
        }
    };
    let derived = hex::encode(key.verifying_key().to_bytes());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(&cfg.signing_key_path) {
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                out.push(Finding::warn(
                    "signing key",
                    format!(
                        "the seed loads (public key {derived}) but {} is mode {mode:03o}",
                        cfg.signing_key_path
                    ),
                    format!(
                        "The seed is this connector's identity. `chmod 600 {}`.",
                        cfg.signing_key_path
                    ),
                ));
                return Some(derived);
            }
        }
    }

    // A .pub written next to the seed (the mint layout) must agree with it.
    let pub_path = std::path::Path::new(&cfg.signing_key_path).with_extension("pub");
    if let Ok(registered) = std::fs::read_to_string(&pub_path) {
        if registered.trim().to_ascii_lowercase() != derived {
            out.push(Finding::fail(
                "signing key",
                format!(
                    "the seed derives public key {derived}, but {} holds {}",
                    pub_path.display(),
                    registered.trim()
                ),
                "The seed and its .pub no longer match; one of them was replaced without the \
                 other. Whichever value your operator has registered is the one that counts: \
                 if it is the .pub, the original seed is gone and you need to re-mint AND \
                 re-register; if the operator has the derived value above, delete the stale \
                 .pub file."
                    .to_string(),
            ));
            return Some(derived);
        }
    }

    out.push(Finding::ok(
        "signing key",
        format!("loads and derives public key {derived}"),
    ));
    Some(derived)
}

fn check_spool(out: &mut Vec<Finding>, cfg: &Inputs) {
    let Some(spool_cfg) = &cfg.spool else {
        out.push(Finding::skip(
            "spool",
            "not configured (optional). One line enables store-and-forward for link \
             outages: spool = \"/var/lib/ajar/spool\" - sealed events then queue on \
             disk during an outage and replay when the link returns.",
        ));
        return;
    };
    match common::spool::Spool::open(spool_cfg) {
        Ok(spool) => {
            let depth = spool.depth_bytes();
            // Prove the connector could append here, not just that we could open it.
            let probe = std::path::Path::new(&spool_cfg.dir).join(".doctor-probe");
            match std::fs::write(&probe, b"probe").and_then(|_| std::fs::remove_file(&probe)) {
                Ok(_) if depth > 0 => out.push(Finding::warn(
                    "spool",
                    format!(
                        "{} is writable and holds {depth} bytes WAITING TO DRAIN",
                        spool_cfg.dir
                    ),
                    "Events queued during an outage are still on disk. If the endpoint \
                     check above passes, the running connector is draining them at its \
                     paced rate - watch connector_drained_total on /metrics. If nothing \
                     is draining, the connector is not running or still cannot reach \
                     the endpoint."
                        .to_string(),
                )),
                Ok(_) => out.push(Finding::ok(
                    "spool",
                    format!("{} is writable, nothing queued", spool_cfg.dir),
                )),
                Err(e) => out.push(Finding::fail(
                    "spool",
                    format!("{} exists but is not writable: {e}", spool_cfg.dir),
                    "The connector will fail to spool during an outage. Fix ownership or \
                     mode on the directory (it must be writable by the connector's user), \
                     and in a container make sure it is a mounted volume, not the \
                     container filesystem."
                        .to_string(),
                )),
            }
        }
        Err(e) => out.push(Finding::fail(
            "spool",
            format!("{e:#}"),
            "The spool directory could not be opened. Check the path exists (or its \
             parent is creatable), the connector's user owns it, and in a container \
             that it is a mounted volume so spooled events survive a restart."
                .to_string(),
        )),
    }
}

fn check_transport(out: &mut Vec<Finding>, cfg: &Inputs) {
    match &cfg.transport {
        Some(common::Transport::UdpMulticast {
            bind,
            group,
            interface,
        }) => {
            // A real join-and-leave, not a guess: SO_REUSE means this is safe
            // next to a running connector, and it exercises the exact
            // interface-selection logic the connector will use.
            match common::udp::open(bind, Some(group), interface.as_deref()) {
                Ok(src) => out.push(Finding::ok("transport", {
                    use common::FrameSource as _;
                    format!("multicast join works ({})", src.describe())
                })),
                Err(e) => out.push(Finding::fail(
                    "transport",
                    format!("{e:#}"),
                    "The connector will fail the same way. On a dual-homed box, set \
                     transport.interface to the IP of the NIC on the surveillance \
                     network (or put that IP in bind), so the group is joined where \
                     the traffic actually is."
                        .to_string(),
                )),
            }
        }
        #[cfg(feature = "serial")]
        Some(common::Transport::Serial { device, baud }) => {
            check_serial_device(out, device, *baud);
        }
        Some(common::Transport::PcapReplay { path, port, .. }) => {
            match std::fs::read(path)
                .map_err(|e| anyhow::anyhow!("reading capture {path}: {e}"))
                .and_then(|data| common::replay::parse_pcap(&data, *port))
            {
                Ok(cap) => out.push(Finding::ok(
                    "transport",
                    format!(
                        "capture {path} parses: {} datagrams to replay ({} skipped as noise)",
                        cap.datagrams.len(),
                        cap.skipped
                    ),
                )),
                Err(e) => out.push(Finding::fail(
                    "transport",
                    format!("{e:#}"),
                    "The connector will refuse the same capture. The error above names \
                     the fix (a pcapng needs converting; an empty result usually means \
                     the port filter does not match what was recorded)."
                        .to_string(),
                )),
            }
        }
        _ => {}
    }
}

fn check_serial_device(out: &mut Vec<Finding>, device: &str, baud: u32) {
    match std::fs::metadata(device) {
        Err(_) => out.push(Finding::fail(
            "transport",
            format!("serial device {device} does not exist"),
            "Nothing is at that path: check the adapter is plugged in and the port \
             name (ls /dev/tty* — a USB adapter is usually /dev/ttyUSB0 or \
             /dev/ttyACM0, and the name can shift when replugged)."
                .to_string(),
        )),
        Ok(_) => {
            // Open read-only and non-blocking: a tty open without O_NONBLOCK can
            // hang on carrier-detect, and the doctor never hangs.
            #[cfg(unix)]
            let opened = {
                use std::os::unix::fs::OpenOptionsExt as _;
                #[cfg(target_os = "linux")]
                const O_NONBLOCK: i32 = 0o4000;
                #[cfg(not(target_os = "linux"))]
                const O_NONBLOCK: i32 = 0x0004;
                std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(O_NONBLOCK)
                    .open(device)
            };
            #[cfg(not(unix))]
            let opened = std::fs::OpenOptions::new().read(true).open(device);
            match opened {
                Ok(_) => out.push(Finding::ok(
                    "transport",
                    format!("serial device {device} present and readable ({baud} baud configured)"),
                )),
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    out.push(Finding::fail(
                        "transport",
                        format!("serial device {device} exists but this user cannot read it"),
                        "Add the connector's service user to the port's group (usually \
                         `usermod -aG dialout <user>`, then log in again), or fix the \
                         device permissions. The connector would retry forever and \
                         publish nothing."
                            .to_string(),
                    ))
                }
                Err(e) => out.push(Finding::fail(
                    "transport",
                    format!("serial device {device}: {e}"),
                    "The device exists but cannot be opened; check nothing else holds \
                     it exclusively and that it is a real serial port."
                        .to_string(),
                )),
            }
        }
    }
}

fn check_registration(
    out: &mut Vec<Finding>,
    cfg: &Inputs,
    sources_dir: Option<&str>,
    derived: Option<&str>,
) {
    let Some(derived) = derived else {
        out.push(Finding::skip(
            "registration",
            "blocked until the signing key loads",
        ));
        return;
    };
    let Some(dir) = sources_dir else {
        out.push(Finding::skip(
            "registration",
            format!(
                "cannot be verified from this box. Ask your operator to confirm that source \
                 {:?} is registered with EXACTLY this public key: {derived}",
                cfg.source_id
            ),
        ));
        return;
    };
    let path = std::path::Path::new(dir).join(format!("{}.pub", cfg.source_id));
    match std::fs::read_to_string(&path) {
        Ok(registered) if registered.trim().to_ascii_lowercase() == derived => {
            out.push(Finding::ok(
                "registration",
                format!("{} matches the loaded seed", path.display()),
            ));
        }
        Ok(registered) => {
            out.push(Finding::fail(
                "registration",
                format!(
                    "{} holds {} but the seed derives {derived}",
                    path.display(),
                    registered.trim()
                ),
                "The sink will refuse every event as a signature failure. Either point \
                 signing_key_path at the seed that belongs to the registered key, or \
                 re-register: copy the new .pub into the sink's sources_dir (or re-run \
                 `ajar-sink mint`) and restart the sink."
                    .to_string(),
            ));
        }
        Err(_) => {
            let registered: Vec<String> = std::fs::read_dir(dir)
                .map(|entries| {
                    entries
                        .filter_map(|e| e.ok())
                        .filter_map(|e| {
                            let p = e.path();
                            (p.extension().and_then(|x| x.to_str()) == Some("pub")).then(|| {
                                p.file_stem()
                                    .unwrap_or_default()
                                    .to_string_lossy()
                                    .into_owned()
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();
            out.push(Finding::fail(
                "registration",
                format!(
                    "no {}.pub in {dir} (registered there: {})",
                    cfg.source_id,
                    if registered.is_empty() {
                        "nothing".to_string()
                    } else {
                        registered.join(", ")
                    }
                ),
                format!(
                    "This source is not registered, so the sink refuses its events as \
                     \"unregistered source\". Register it: `ajar-sink mint {} {dir}` (or copy \
                     an existing .pub there) and restart the sink. If one of the names listed \
                     above was meant to be this connector, fix source_id in the config instead.",
                    cfg.source_id
                ),
            ));
        }
    }
}

async fn check_endpoint(
    out: &mut Vec<Finding>,
    cfg: &Inputs,
    timeout: Duration,
) -> (Option<net::Endpoint>, Option<net::ServerInfo>) {
    let endpoints = match net::parse_urls(&cfg.nats_url) {
        Ok(eps) => eps,
        Err(e) => {
            out.push(Finding::fail(
                "endpoint",
                format!("nats_url {:?}: {e:#}", cfg.nats_url),
                "nats_url must look like nats://host:4222 or tls://host:4222, with a \
                 comma-separated list for failover. Use the exact endpoint(s) the \
                 operator sent back in registration step 3."
                    .to_string(),
            ));
            return (None, None);
        }
    };
    // A failover list means EVERY endpoint gets probed: a dead standby is
    // exactly what this tool exists to find before the drill does.
    if endpoints.len() > 1 {
        let mut dead: Vec<String> = Vec::new();
        for ep in &endpoints[1..] {
            match net::dial(ep, timeout).await {
                net::Dial::Connected(_) => {}
                net::Dial::NoDns(e) | net::Dial::NoAnswer(e) => {
                    dead.push(format!("{} ({e})", ep.addr()))
                }
            }
        }
        if dead.is_empty() {
            out.push(Finding::ok(
                "failover",
                format!(
                    "all {} endpoints in the failover list answer",
                    endpoints.len()
                ),
            ));
        } else {
            out.push(Finding::warn(
                "failover",
                format!("standby endpoint(s) not answering: {}", dead.join("; ")),
                "The connector still runs on the surviving endpoint(s), but the two-box \
                 story is one box short. Fix the standby before you need it."
                    .to_string(),
            ));
        }
    }
    let ep = endpoints
        .into_iter()
        .next()
        .expect("parse_urls yields at least one endpoint");
    match net::dial(&ep, timeout).await {
        net::Dial::Connected(mut stream) => {
            let greeting = net::read_info(&mut stream, Duration::from_millis(1500)).await;
            match greeting {
                Ok(Some(info)) => {
                    out.push(Finding::ok(
                        "endpoint",
                        format!(
                            "{} answers and speaks NATS (tls_required={})",
                            ep.addr(),
                            info.tls_required
                        ),
                    ));
                    (Some(ep), Some(info))
                }
                Ok(None) => {
                    out.push(Finding::ok(
                        "endpoint",
                        format!(
                            "{} answers; no cleartext greeting, so the server is likely in \
                             TLS-first mode",
                            ep.addr()
                        ),
                    ));
                    (Some(ep), None)
                }
                Err(e) => {
                    out.push(Finding::fail(
                        "endpoint",
                        format!("{} answers but does not speak NATS: {e:#}", ep.addr()),
                        "Something is listening there, but it is not a NATS server. The usual \
                         cause is the wrong port (a metrics or HTTP port instead of the client \
                         port). Check nats_url against what the operator sent."
                            .to_string(),
                    ));
                    (None, None)
                }
            }
        }
        net::Dial::NoDns(e) => {
            out.push(Finding::fail(
                "endpoint",
                format!("{:?} does not resolve here: {e}", ep.host),
                "This machine cannot look the name up, which usually means the wrong network \
                 (the endpoint may be a name inside the operator's enclave) or missing DNS. \
                 Try the IP form of the endpoint if the operator gave one, and confirm which \
                 network this box must sit on."
                    .to_string(),
            ));
            (None, None)
        }
        net::Dial::NoAnswer(e) => {
            out.push(Finding::fail(
                "endpoint",
                format!("{} resolved but did not answer: {e}", ep.addr()),
                "The name is right but nothing accepted the connection: either NATS is not \
                 listening on that port or a firewall between here and there drops it. \
                 Confirm host:port with the operator; if it is correct, the firewall request \
                 goes to whoever owns the network path."
                    .to_string(),
            ));
            (None, None)
        }
    }
}

/// Returns the (ca, cert, key) paths when the policy is mTLS.
fn check_policy(
    out: &mut Vec<Finding>,
    policy: &tls::Policy,
    greeting: Option<&net::ServerInfo>,
) -> Option<(String, String, String)> {
    match policy {
        tls::Policy::Mtls { ca, cert, key } => {
            out.push(Finding::ok(
                "tls policy",
                "AJAR_TLS_CA, AJAR_TLS_CERT and AJAR_TLS_KEY are all set (mTLS)",
            ));
            Some((ca.clone(), cert.clone(), key.clone()))
        }
        tls::Policy::Partial { set, missing } => {
            out.push(Finding::fail(
                "tls policy",
                format!(
                    "partial TLS configuration: {} set, {} missing",
                    set.join(", "),
                    missing.join(", ")
                ),
                "The runtime refuses a partial TLS config rather than guessing, so the \
                 connector will not start like this. Set the missing variable(s) to the files \
                 the operator issued, or unset all three for a local cleartext dev run."
                    .to_string(),
            ));
            None
        }
        tls::Policy::Cleartext { required: true } => {
            out.push(Finding::fail(
                "tls policy",
                "TLS is required (tls:// URL or AJAR_REQUIRE_TLS) but no AJAR_TLS_* is set",
                "The runtime refuses to connect in cleartext when TLS is demanded. Export \
                 AJAR_TLS_CA, AJAR_TLS_CERT and AJAR_TLS_KEY pointing at the CA bundle, \
                 client certificate and key from your operator (the onboarding guide's \
                 Production behaviour section shows the exact block)."
                    .to_string(),
            ));
            None
        }
        tls::Policy::Cleartext { required: false } => {
            if greeting.map(|g| g.tls_required).unwrap_or(false) {
                out.push(Finding::fail(
                    "tls policy",
                    "no AJAR_TLS_* is set, but the server demands TLS",
                    "The endpoint answered with tls_required=true: every cleartext connection \
                     will be dropped. Export AJAR_TLS_CA, AJAR_TLS_CERT and AJAR_TLS_KEY with \
                     the files from your operator, and use a tls:// URL so the demand is \
                     explicit on your side too."
                        .to_string(),
                ));
            } else {
                out.push(Finding::warn(
                    "tls policy",
                    "no AJAR_TLS_* set: cleartext, dev only",
                    "Fine against a local dev broker, never for a real link. The production \
                     setup is the three AJAR_TLS_* variables plus a tls:// URL."
                        .to_string(),
                ));
            }
            None
        }
    }
}

fn check_certificate_files(
    out: &mut Vec<Finding>,
    cfg: &Inputs,
    ca: &str,
    cert: &str,
    key: &str,
) -> Option<certs::ClientIdentity> {
    // The CA file first: it is the smaller file and the more common mixup.
    match certs::load_pem_certs(ca).and_then(|c| certs::inspect_der(c[0].as_ref())) {
        Ok(info) if !info.is_ca => out.push(Finding::warn(
            "certificate files",
            format!("{ca} parses, but its first certificate is not marked as a CA"),
            "AJAR_TLS_CA must hold the operator's CA bundle (the roots that signed the \
             SERVER certificate), not a copy of a server or client certificate. If the \
             handshake below fails with an unknown issuer, this is why."
                .to_string(),
        )),
        Ok(_) => {}
        Err(e) => {
            out.push(Finding::fail(
                "certificate files",
                format!("{e:#}"),
                "AJAR_TLS_CA must be a PEM file holding the operator's CA certificate(s). \
                 Re-download or re-copy it from the operator's registration reply."
                    .to_string(),
            ));
            return None;
        }
    }

    let identity = match certs::load_client_identity(cert, key) {
        Ok(id) => id,
        Err(e) => {
            out.push(Finding::fail(
                "certificate files",
                format!("{e:#}"),
                "AJAR_TLS_CERT must be your client certificate (PEM) and AJAR_TLS_KEY its \
                 private key (PEM). The most common slip is the two paths swapped; the next \
                 most common is pointing AJAR_TLS_KEY at the Ed25519 signing seed, which is a \
                 different key entirely."
                    .to_string(),
            ));
            return None;
        }
    };

    let now = certs::now_unix();
    if identity.leaf.not_after < now {
        out.push(Finding::fail(
            "certificate files",
            format!(
                "the client certificate expired ({})",
                identity.leaf.not_after_text
            ),
            "Ask the operator to reissue your client certificate. Until then the server \
             will refuse the handshake."
                .to_string(),
        ));
    } else if identity.leaf.not_before > now {
        out.push(Finding::fail(
            "certificate files",
            format!(
                "the client certificate is not valid until {}",
                identity.leaf.not_before_text
            ),
            "Either this machine's clock is behind (run `date -u` and compare with a clock \
             you trust) or the certificate was postdated. A skewed clock also corrupts \
             event timestamps, so fix it either way."
                .to_string(),
        ));
    } else {
        match &identity.leaf.common_name {
            Some(cn) if *cn == cfg.source_id => out.push(Finding::ok(
                "certificate files",
                format!(
                    "client certificate CN {cn:?} matches source_id, valid until {}",
                    identity.leaf.not_after_text
                ),
            )),
            Some(cn) => out.push(Finding::warn(
                "certificate files",
                format!(
                    "client certificate CN is {cn:?} but source_id is {:?}",
                    cfg.source_id
                ),
                "The client certificate's CN is the connector's transport identity and must \
                 be exactly the source_id. Some operators map identities differently, but if \
                 the server refuses you or the sink attributes events oddly, this mismatch \
                 is the first thing to fix (reissue the certificate with the right CN)."
                    .to_string(),
            )),
            None => out.push(Finding::warn(
                "certificate files",
                "the client certificate has no CN".to_string(),
                "The convention is CN = source_id. Confirm with the operator that your \
                 certificate is mapped to your registered identity some other way."
                    .to_string(),
            )),
        }
    }
    Some(identity)
}

async fn check_handshake(
    out: &mut Vec<Finding>,
    ep: &net::Endpoint,
    ca: &str,
    identity: Option<certs::ClientIdentity>,
    source_id: &str,
    timeout: Duration,
) -> Option<certs::CertInfo> {
    let client = identity.map(|id| (id.chain, id.key));
    match tls::probe(ep, ca, client, source_id, timeout).await {
        Ok(hs) => {
            match &hs.outcome {
                Ok(detail) => out.push(Finding::ok("tls handshake", detail.clone())),
                Err(d) => out.push(Finding::fail(
                    "tls handshake",
                    d.problem.clone(),
                    d.fix.clone(),
                )),
            }
            hs.server_cert
        }
        Err(e) => {
            out.push(Finding::fail(
                "tls handshake",
                format!("{e:#}"),
                "Fix the file named above and re-run; the handshake was not attempted.".to_string(),
            ));
            None
        }
    }
}

fn check_clock(out: &mut Vec<Finding>, server_cert: Option<&certs::CertInfo>) {
    let Some(cert) = server_cert else {
        out.push(Finding::skip(
            "clock",
            "no server certificate seen to compare the clock against; run `date -u` and \
             compare with a clock you trust",
        ));
        return;
    };
    let now = certs::now_unix();
    if now < cert.not_before {
        out.push(Finding::fail(
            "clock",
            format!(
                "this machine believes the time is before the server certificate even \
                 existed ({})",
                cert.not_before_text
            ),
            "The local clock is almost certainly behind. Fix it (NTP where available, \
             `date -u -s` on an air-gapped box) before trusting any timestamps this \
             connector produces."
                .to_string(),
        ));
    } else if now > cert.not_after {
        out.push(Finding::warn(
            "clock",
            format!(
                "the server certificate reads as expired ({}); either it truly is, or this \
                 clock is ahead",
                cert.not_after_text
            ),
            "Run `date -u` and compare with a clock you trust before blaming the \
             certificate."
                .to_string(),
        ));
    } else {
        out.push(Finding::ok(
            "clock",
            format!(
                "local clock sits inside the server certificate's validity ({} to {})",
                cert.not_before_text, cert.not_after_text
            ),
        ));
    }
}
