// SPDX-License-Identifier: Apache-2.0
//! An instance: one enrolled connector on this machine, in `instances/<connector-id>/`. It holds
//! the invite's files, `instance.toml` (what the invite and `join` decided), the operator's
//! `settings.toml`, the `config.toml` written from both at every start, the log and the pid.

use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use ajar_doctor::report::Finding;
use ajar_tooling::invite::{CheckedInvite, ConnectorId, Invite, InviteFile};
use ajar_tooling::request::RequestKeys;
use anyhow::Context as _;
use rcgen::{KeyPair, PublicKeyData};
use serde::{Deserialize, Serialize};
use tempfile::TempDir;
use toml::{Table, Value};

use crate::connectors::ConnectorVersion;
use crate::context::Root;

const RECORD_FORMAT: u32 = 1;
const RECORD_FILE: &str = "instance.toml";
const SETTINGS_FILE: &str = "settings.toml";
const CONNECTOR_CONFIG_FILE: &str = "config.toml";
const PID_FILE: &str = "connector.pid";

/// Config keys that come from the invite or from `join`, so `settings.toml` may not set them.
/// Of the invite's `[transport]`, only the local keys below may be set.
const PRODUCER_KEYS: [&str; 4] = [
    "source_id",
    "nats_url",
    "subject_prefix",
    "signing_key_path",
];
/// The `[transport]` keys that depend on this machine: the network card a multicast or DDS
/// feed arrives on, and the serial device.
const LOCAL_TRANSPORT_KEYS: [&str; 3] = ["interface", "interface_ip", "device"];
const CONSUMER_KEYS: [&str; 4] = [
    "nats_url",
    "egress_subject",
    "egress_verifying_key",
    "target",
];

/// `instance.toml`: changed only by this tool.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceRecord {
    pub format: u32,
    pub version: ConnectorVersion,
    /// The consumer's delivery target. Producers have none.
    pub target: Option<String>,
    pub invite: Invite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    Running(u32),
    Stopped,
    /// A pid file whose process is gone: the connector exited without `stop`.
    Died(u32),
}

#[derive(Debug)]
pub struct Instance {
    dir: PathBuf,
    pub record: InstanceRecord,
}

impl Instance {
    pub fn load(root: &Root, connector_id: &ConnectorId) -> anyhow::Result<Instance> {
        let dir = root.instance_dir(connector_id);
        if !dir.exists() {
            anyhow::bail!(
                "there is no instance {connector_id} in {}",
                root.instances_dir().display()
            );
        }
        Instance::load_dir(dir)
    }

    pub fn load_all(root: &Root) -> anyhow::Result<Vec<Instance>> {
        let instances_dir = root.instances_dir();
        let mut instances = Vec::new();
        for entry in std::fs::read_dir(&instances_dir)
            .with_context(|| format!("reading {}", instances_dir.display()))?
        {
            let dir = entry
                .with_context(|| format!("reading {}", instances_dir.display()))?
                .path();
            let hidden = dir
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with('.'));
            if !hidden {
                instances.push(Instance::load_dir(dir)?);
            }
        }
        instances.sort_by(|a, b| a.connector_id().cmp(b.connector_id()));
        Ok(instances)
    }

    fn load_dir(dir: PathBuf) -> anyhow::Result<Instance> {
        let record_path = dir.join(RECORD_FILE);
        let text = std::fs::read_to_string(&record_path)
            .with_context(|| format!("reading {}", record_path.display()))?;
        let record: InstanceRecord = toml::from_str(&text)
            .with_context(|| format!("{} is not valid", record_path.display()))?;
        if record.format != RECORD_FORMAT {
            anyhow::bail!(
                "{} is format {} and this tool reads format {RECORD_FORMAT}",
                record_path.display(),
                record.format
            );
        }
        let folder_name = dir.file_name().and_then(|name| name.to_str());
        if folder_name != Some(record.invite.connector_id().as_str()) {
            anyhow::bail!(
                "{} is for connector {}, not for its folder's name",
                record_path.display(),
                record.invite.connector_id()
            );
        }
        Ok(Instance { dir, record })
    }

    /// Points the instance at another installed version of its connector type.
    pub fn set_version(&mut self, root: &Root, version: ConnectorVersion) -> anyhow::Result<()> {
        let old = std::mem::replace(&mut self.record.version, version);
        if let Err(e) = self.binary(root) {
            self.record.version = old;
            return Err(e);
        }
        self.save_record()
    }

    /// Changes where a consumer delivers.
    pub fn set_target(&mut self, target: String) -> anyhow::Result<()> {
        if matches!(self.record.invite, Invite::Producer(_)) {
            anyhow::bail!("{} is a producer, which has no target", self.connector_id());
        }
        self.record.target = Some(target);
        self.save_record()
    }

    fn save_record(&self) -> anyhow::Result<()> {
        // Written beside the record and renamed over it, so a crash never leaves half a file.
        let record_path = self.dir.join(RECORD_FILE);
        let new_path = self.dir.join(format!("{RECORD_FILE}.new"));
        std::fs::write(&new_path, toml::to_string(&self.record)?)
            .with_context(|| format!("writing {}", new_path.display()))?;
        std::fs::rename(&new_path, &record_path)
            .with_context(|| format!("replacing {}", record_path.display()))
    }

    /// Writes `config.toml` from the current `settings.toml` and runs the doctor on it, with
    /// the TLS files the connector runs with.
    pub fn preflight(&self) -> anyhow::Result<Vec<Finding>> {
        let config_path = self.write_connector_config()?;
        let path = |file: InviteFile| self.file(file).to_string_lossy().into_owned();
        let options = ajar_doctor::Options {
            role: match &self.record.invite {
                Invite::Producer(_) => ajar_doctor::Role::Producer,
                Invite::Consumer(c) => ajar_doctor::Role::Consumer {
                    connector_id: c.connector_id.to_string(),
                },
            },
            config_path: config_path.to_string_lossy().into_owned(),
            tls_files: Some(ajar_doctor::TlsFiles {
                ca: path(InviteFile::CaCert),
                cert: path(InviteFile::MtlsCert),
                key: path(InviteFile::MtlsKey),
            }),
            timeout: Duration::from_secs(5),
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("starting the preflight")?;
        Ok(runtime.block_on(ajar_doctor::run(&options)))
    }

    pub fn connector_id(&self) -> &ConnectorId {
        self.record.invite.connector_id()
    }

    pub fn log_path(&self) -> PathBuf {
        self.dir.join("connector.log")
    }

    /// The installed binary for the instance's connector type and version.
    pub fn binary(&self, root: &Root) -> anyhow::Result<PathBuf> {
        let connector_type = self.record.invite.connector_type();
        let version_dir = root
            .connectors_dir()
            .join(connector_type.as_str())
            .join(self.record.version.to_string());
        if !version_dir.is_dir() {
            match &self.record.version {
                ConnectorVersion::Local => anyhow::bail!(
                    "{connector_type} local is not installed: put the binary in the current \
                     folder as ajar-{connector_type} and run `ajar-connectors install \
                     {connector_type}`"
                ),
                ConnectorVersion::Release(version) => anyhow::bail!(
                    "{connector_type} {version} is not installed: run `ajar-connectors install \
                     {connector_type}@{version}`"
                ),
            }
        }
        crate::connectors::installed_binary(&version_dir)?
            .canonicalize()
            .context("resolving the connector binary")
    }

    /// The connector's config: `settings` with the invite's and `join`'s keys added. A key in
    /// `settings` that those set is refused.
    fn connector_config(&self, mut settings: Table) -> anyhow::Result<Table> {
        let file = |name: &str| self.dir.join(name).to_string_lossy().into_owned();
        let (own_keys, values): (&[&str], Vec<(&str, Value)>) = match &self.record.invite {
            Invite::Producer(p) => {
                let subject_prefix = p
                    .subject
                    .strip_suffix(&format!(".{}", p.connector_id))
                    .with_context(|| {
                        format!(
                            "the invite's subject {} does not end in the connector ID",
                            p.subject
                        )
                    })?;
                let mut transport = Table::try_from(&p.transport)?;
                if let Some(local) = settings.remove("transport") {
                    let Value::Table(local) = local else {
                        anyhow::bail!("{SETTINGS_FILE} sets transport, which must be a table");
                    };
                    for (key, value) in local {
                        if !LOCAL_TRANSPORT_KEYS.contains(&key.as_str()) {
                            anyhow::bail!(
                                "{SETTINGS_FILE} sets transport.{key}, which comes from the \
                                 invite; locally only {} can be set",
                                LOCAL_TRANSPORT_KEYS.join(", ")
                            );
                        }
                        transport.insert(key, value);
                    }
                }
                let values = vec![
                    ("source_id", p.connector_id.as_str().into()),
                    ("nats_url", p.nats_url.as_str().into()),
                    ("subject_prefix", subject_prefix.into()),
                    (
                        "signing_key_path",
                        file(InviteFile::EventSigningKey.member_name()).into(),
                    ),
                    ("transport", Value::Table(transport)),
                ];
                (&PRODUCER_KEYS, values)
            }
            Invite::Consumer(c) => {
                let target = self
                    .record
                    .target
                    .as_deref()
                    .context("the consumer has no target")?;
                let values = vec![
                    ("nats_url", c.nats_url.as_str().into()),
                    ("egress_subject", c.egress_subject.as_str().into()),
                    (
                        "egress_verifying_key",
                        file(InviteFile::EgressPublicKey.member_name()).into(),
                    ),
                    ("target", target.into()),
                ];
                (&CONSUMER_KEYS, values)
            }
        };
        if let Some(key) = own_keys.iter().find(|key| settings.contains_key(**key)) {
            anyhow::bail!(
                "{SETTINGS_FILE} sets {key}, which comes from the invite or from join and \
                 can't be set locally"
            );
        }
        for (key, value) in values {
            settings.insert(key.to_owned(), value);
        }
        Ok(settings)
    }

    /// Writes `config.toml` from `settings.toml` and the invite, and returns its path.
    fn write_connector_config(&self) -> anyhow::Result<PathBuf> {
        let settings_path = self.dir.join(SETTINGS_FILE);
        let settings_text = std::fs::read_to_string(&settings_path)
            .with_context(|| format!("reading {}", settings_path.display()))?;
        let settings: Table = toml::from_str(&settings_text)
            .with_context(|| format!("{} is not valid TOML", settings_path.display()))?;
        let config = self.connector_config(settings)?;
        let config_path = self.dir.join(CONNECTOR_CONFIG_FILE);
        let config_text = format!(
            "# Written by ajar-connectors at every start from {RECORD_FILE} and {SETTINGS_FILE}.\n\
             # Change {SETTINGS_FILE} instead: this file is replaced.\n\n{}",
            toml::to_string(&config)?
        );
        std::fs::write(&config_path, config_text)
            .with_context(|| format!("writing {}", config_path.display()))?;
        Ok(config_path)
    }

    /// The invite's file in the instance folder.
    pub fn file(&self, file: InviteFile) -> PathBuf {
        self.dir.join(file.member_name())
    }

    pub fn state(&self) -> anyhow::Result<ProcessState> {
        let pid_path = self.dir.join(PID_FILE);
        let text = match std::fs::read_to_string(&pid_path) {
            Ok(text) => text,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(ProcessState::Stopped),
            Err(e) => return Err(e).with_context(|| format!("reading {}", pid_path.display())),
        };
        let pid: u32 = text
            .trim()
            .parse()
            .with_context(|| format!("{} holds no pid", pid_path.display()))?;
        if self.runs_config(pid) {
            Ok(ProcessState::Running(pid))
        } else {
            Ok(ProcessState::Died(pid))
        }
    }

    /// True while `pid`'s command line holds this instance's config. A pid reused by another
    /// process, or by another instance's connector, is never taken for this one.
    fn runs_config(&self, pid: u32) -> bool {
        let config = self.dir.join(CONNECTOR_CONFIG_FILE);
        std::fs::read(format!("/proc/{pid}/cmdline")).is_ok_and(|cmdline| {
            cmdline
                .split(|byte| *byte == 0)
                .any(|arg| arg == config.as_os_str().as_bytes())
        })
    }

    /// Writes `config.toml` and starts the connector in the background, logging to
    /// `connector.log`. Fails when the connector exits within its first seconds.
    pub fn start(&self, root: &Root) -> anyhow::Result<u32> {
        const SETTLE: Duration = Duration::from_secs(2);
        if !cfg!(target_os = "linux") {
            anyhow::bail!(
                "start runs connectors on Linux only; use `ajar-connectors run` to run one in \
                 the foreground"
            );
        }
        match self.state()? {
            ProcessState::Running(pid) => {
                anyhow::bail!("{} is already running as pid {pid}", self.connector_id())
            }
            ProcessState::Died(_) => remove_file(&self.dir.join(PID_FILE))?,
            ProcessState::Stopped => {}
        }

        let config_path = self.write_connector_config()?;

        // Kept to one old copy, so a noisy feed can't fill the disk.
        const LOG_LIMIT: u64 = 50 * 1024 * 1024;
        let log_path = self.log_path();
        if std::fs::metadata(&log_path).is_ok_and(|m| m.len() > LOG_LIMIT) {
            let old = log_path.with_extension("log.1");
            std::fs::rename(&log_path, &old)
                .with_context(|| format!("moving {} to {}", log_path.display(), old.display()))?;
        }
        let log = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&log_path)
            .with_context(|| format!("opening {}", log_path.display()))?;
        let log_start = log.metadata()?.len();
        let binary = self.binary(root)?;
        let tls_file = |file: InviteFile| self.file(file);
        let mut child = Command::new(&binary)
            .arg(&config_path)
            .env("AJAR_TLS_CA", tls_file(InviteFile::CaCert))
            .env("AJAR_TLS_CERT", tls_file(InviteFile::MtlsCert))
            .env("AJAR_TLS_KEY", tls_file(InviteFile::MtlsKey))
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log)
            // Its own process group, so a signal to the terminal's group doesn't reach it.
            .process_group(0)
            .spawn()
            .with_context(|| format!("starting {}", binary.display()))?;
        let pid = child.id();
        if let Err(e) = write_new(&self.dir.join(PID_FILE), pid.to_string().as_bytes(), 0o644) {
            // Without a pid file nothing could find or stop it.
            let _ = child.kill();
            let _ = child.wait();
            return Err(e);
        }

        let started = Instant::now();
        while started.elapsed() < SETTLE {
            if let Some(status) = child.try_wait()? {
                const SHOWN_BYTES: u64 = 4096;
                remove_file(&self.dir.join(PID_FILE))?;
                let mut file = File::open(&log_path)
                    .with_context(|| format!("reading {}", log_path.display()))?;
                let end = file.metadata()?.len();
                file.seek(SeekFrom::Start(
                    log_start.max(end.saturating_sub(SHOWN_BYTES)),
                ))?;
                let mut bytes = Vec::new();
                file.read_to_end(&mut bytes)?;
                anyhow::bail!(
                    "{} exited at once ({status}). The end of {}:\n{}",
                    self.connector_id(),
                    log_path.display(),
                    String::from_utf8_lossy(&bytes)
                );
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Ok(pid)
    }

    /// Stops the connector with SIGTERM, or SIGKILL when `force`. Fails when it is still
    /// running after the wait.
    pub fn stop(&self, force: bool) -> anyhow::Result<()> {
        const WAIT: Duration = Duration::from_secs(10);
        let pid = match self.state()? {
            ProcessState::Stopped => anyhow::bail!("{} is not running", self.connector_id()),
            ProcessState::Died(_) => return remove_file(&self.dir.join(PID_FILE)),
            ProcessState::Running(pid) => pid,
        };
        let signal = if force { "-KILL" } else { "-TERM" };
        let status = Command::new("kill")
            .args([signal, &pid.to_string()])
            .status()
            .context("running kill")?;
        if !status.success() {
            anyhow::bail!("kill {signal} {pid} failed ({status})");
        }
        let started = Instant::now();
        while self.runs_config(pid) {
            if started.elapsed() > WAIT {
                anyhow::bail!(
                    "{} is still running as pid {pid}: run `ajar-connectors stop {} --force`",
                    self.connector_id(),
                    self.connector_id()
                );
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        remove_file(&self.dir.join(PID_FILE))
    }

    /// Removes the instance's folder, with its keys. Refused while the connector runs.
    pub fn remove(self) -> anyhow::Result<()> {
        if let ProcessState::Running(pid) = self.state()? {
            anyhow::bail!(
                "{} is running as pid {pid}: stop it first",
                self.connector_id()
            );
        }
        std::fs::remove_dir_all(&self.dir)
            .with_context(|| format!("removing {}", self.dir.display()))
    }
}

/// An invite unpacked into a hidden folder, becoming an instance: `stage` checks the invite,
/// `prepare` writes the instance's files, and `commit` moves it into place. Dropping it before
/// the commit removes the folder.
#[derive(Debug)]
pub struct StagedInstance {
    staging: TempDir,
    invite: Invite,
    /// Set by `prepare`.
    instance: Option<Instance>,
    /// The instance's final folder.
    dir: PathBuf,
    /// The request whose keys it took, removed on commit.
    request_dir: Option<PathBuf>,
}

impl StagedInstance {
    /// Checks the invite and unpacks it. An invite without private keys takes them from this
    /// machine's request.
    pub fn stage(root: &Root, invite_path: &Path) -> anyhow::Result<StagedInstance> {
        let staging = tempfile::Builder::new()
            .prefix(".joining-")
            .tempdir_in(root.instances_dir())
            .with_context(|| format!("creating a folder in {}", root.instances_dir().display()))?;
        let staged_dir = staging.path().join("instance");
        let checked = CheckedInvite::open(invite_path, &staged_dir)?;
        let invite = checked.invite().clone();
        let dir = root.instance_dir(invite.connector_id());
        if dir.exists() {
            anyhow::bail!(
                "instance {} already exists in {}",
                invite.connector_id(),
                dir.display()
            );
        }
        let request_dir = match checked.carries_secrets() {
            true => None,
            false => Some(take_request_keys(root, &invite, &staged_dir)?),
        };
        Ok(StagedInstance {
            staging,
            invite,
            instance: None,
            dir,
            request_dir,
        })
    }

    pub fn invite(&self) -> &Invite {
        &self.invite
    }

    /// True when the invite held the private keys, which makes the invite file a secret.
    pub fn invite_held_keys(&self) -> bool {
        self.request_dir.is_none()
    }

    /// The instance's final folder.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Writes `settings.toml`, `instance.toml` and `config.toml` for `version` of the invite's
    /// connector type, which must be installed. `settings` is copied to `settings.toml`; without
    /// it a commented one is written.
    pub fn prepare(
        &mut self,
        root: &Root,
        version: ConnectorVersion,
        target: Option<String>,
        settings: Option<&Path>,
    ) -> anyhow::Result<&Instance> {
        match (&self.invite, &target) {
            (Invite::Producer(_), Some(_)) => anyhow::bail!("a producer has no target"),
            (Invite::Consumer(c), None) => {
                anyhow::bail!(
                    "{} delivers to a target, and none was given",
                    c.connector_type
                )
            }
            _ => {}
        }
        let instance = Instance {
            dir: self.staging.path().join("instance"),
            record: InstanceRecord {
                format: RECORD_FORMAT,
                version,
                target,
                invite: self.invite.clone(),
            },
        };
        instance.binary(root)?;

        let settings_text = match settings {
            Some(path) => std::fs::read_to_string(path)
                .with_context(|| format!("reading {}", path.display()))?,
            None => settings_template(&instance.record.invite),
        };
        // Checked here so the error names the operator's file, not the staged copy.
        if let Some(path) = settings {
            toml::from_str::<Table>(&settings_text)
                .with_context(|| format!("{} is not valid TOML", path.display()))?;
        }
        write_new(
            &instance.dir.join(SETTINGS_FILE),
            settings_text.as_bytes(),
            0o644,
        )?;
        write_new(
            &instance.dir.join(RECORD_FILE),
            toml::to_string(&instance.record)?.as_bytes(),
            0o644,
        )?;
        instance.write_connector_config()?;
        Ok(self.instance.insert(instance))
    }

    /// Moves the prepared instance to `instances/<connector-id>/`.
    pub fn commit(self) -> anyhow::Result<Instance> {
        let instance = self.instance.context("the instance was not prepared")?;
        std::fs::rename(&instance.dir, &self.dir)
            .with_context(|| format!("moving the instance into {}", self.dir.display()))?;
        if let Some(request_dir) = &self.request_dir {
            std::fs::remove_dir_all(request_dir)
                .with_context(|| format!("removing {}", request_dir.display()))?;
        }
        let instance = Instance {
            dir: self.dir,
            record: instance.record,
        };
        // The staged config names files in the staging folder.
        instance.write_connector_config()?;
        Ok(instance)
    }
}

/// Keeps a request's private keys in `instances/.requests/<connector-id>/` until the invite
/// that answers it is joined, and returns that folder.
pub fn store_request_keys(
    root: &Root,
    connector_id: &ConnectorId,
    keys: &RequestKeys,
) -> anyhow::Result<PathBuf> {
    if root.instance_dir(connector_id).exists() {
        anyhow::bail!("instance {connector_id} already exists");
    }
    let dir = root.requests_dir().join(connector_id.as_str());
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(root.requests_dir())
        .with_context(|| format!("creating {}", root.requests_dir().display()))?;
    DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .with_context(|| {
            format!(
                "a request for {connector_id} already exists in {}",
                dir.display()
            )
        })?;
    write_new(
        &dir.join(InviteFile::MtlsKey.member_name()),
        keys.mtls_key_pem.as_bytes(),
        0o600,
    )?;
    if let Some(signing_key) = &keys.event_signing_key {
        write_new(
            &dir.join(InviteFile::EventSigningKey.member_name()),
            hex::encode(signing_key.to_bytes()).as_bytes(),
            0o600,
        )?;
    }
    Ok(dir)
}

/// Copies a request's private keys into a staged instance, after checking that the invite's
/// certificate is for that mTLS key. Returns the request folder.
fn take_request_keys(root: &Root, invite: &Invite, staged_dir: &Path) -> anyhow::Result<PathBuf> {
    let connector_id = invite.connector_id();
    let request_dir = root.requests_dir().join(connector_id.as_str());
    if !request_dir.is_dir() {
        anyhow::bail!(
            "the invite holds no private keys, so it answers a request, and no request for \
             {connector_id} was made on this machine; join it where the request was made"
        );
    }
    let mut keys = vec![InviteFile::MtlsKey];
    if matches!(invite, Invite::Producer(_)) {
        keys.push(InviteFile::EventSigningKey);
    }
    for file in keys {
        let from = request_dir.join(file.member_name());
        let bytes = std::fs::read(&from).with_context(|| format!("reading {}", from.display()))?;
        write_new(&staged_dir.join(file.member_name()), &bytes, 0o600)?;
    }

    let key_path = staged_dir.join(InviteFile::MtlsKey.member_name());
    let key_pem = std::fs::read_to_string(&key_path)
        .with_context(|| format!("reading {}", key_path.display()))?;
    let key = KeyPair::from_pem(&key_pem)
        .with_context(|| format!("{} is not a private key", key_path.display()))?;
    let cert_path = staged_dir.join(InviteFile::MtlsCert.member_name());
    let cert_pem =
        std::fs::read(&cert_path).with_context(|| format!("reading {}", cert_path.display()))?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(&cert_pem)
        .map_err(|e| anyhow::anyhow!("the invite's mtls.crt is not a PEM certificate: {e}"))?;
    let cert = pem
        .parse_x509()
        .map_err(|e| anyhow::anyhow!("the invite's mtls.crt is not a certificate: {e}"))?;
    if *cert.public_key().subject_public_key.data != *key.der_bytes() {
        anyhow::bail!(
            "the invite's certificate is not for the key this machine's request made for \
             {connector_id}: it answers another request"
        );
    }
    Ok(request_dir)
}

/// A `settings.toml` with only comments: the keys an operator may set for this role.
fn settings_template(invite: &Invite) -> String {
    let (keys, own) = match invite {
        Invite::Producer(_) => (
            "default_hostility, marking, sensor, entity_map, spool, options, mapping, and in \
             [transport] only interface, interface_ip or device",
            PRODUCER_KEYS.as_slice(),
        ),
        Invite::Consumer(_) => (
            "the connector's own tables, such as [tak], [deliver], [mapping] or [sapient]",
            CONSUMER_KEYS.as_slice(),
        ),
    };
    format!(
        "# Local settings for {id}, added to its config at every start.\n\
         # Set here: {keys}.\n\
         # Set by the invite and join, so not here: {own}.\n\
         # The connector's README and example config list every option.\n",
        id = invite.connector_id(),
        own = own.join(", "),
    )
}

fn write_new(path: &Path, bytes: &[u8], mode: u32) -> anyhow::Result<()> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .and_then(|mut f| f.write_all(bytes))
        .with_context(|| format!("writing {}", path.display()))
}

fn remove_file(path: &Path) -> anyhow::Result<()> {
    std::fs::remove_file(path).with_context(|| format!("removing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use ajar_tooling::invite::{ConnectorType, ConsumerInvite};

    use super::*;
    use crate::testutil::{create, machine, producer, request_keys, write_answer, write_invite};

    fn version() -> ConnectorVersion {
        ConnectorVersion::try_from("0.6.7".to_owned()).unwrap()
    }

    #[test]
    fn invite_answering_this_machines_request_takes_its_keys() {
        let machine = machine();
        let keys = request_keys(&machine);
        let invite = write_answer(&machine, &producer(), &keys.mtls_key_pem);
        let instance = create(&machine.root, &invite, version(), None, None).unwrap();
        assert_eq!(
            std::fs::read_to_string(instance.file(InviteFile::MtlsKey)).unwrap(),
            keys.mtls_key_pem
        );
        assert!(instance.file(InviteFile::EventSigningKey).is_file());
        assert!(!machine.root.requests_dir().join("radar-1").exists());
    }

    #[test]
    fn invite_for_another_key_is_refused() {
        let machine = machine();
        request_keys(&machine);
        let other = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let invite = write_answer(&machine, &producer(), &other.serialize_pem());
        let err = create(&machine.root, &invite, version(), None, None).unwrap_err();
        assert!(err.to_string().contains("answers another request"), "{err}");
        assert!(machine.root.requests_dir().join("radar-1").exists());
    }

    #[test]
    fn producer_config_adds_the_invite_to_the_settings() {
        let machine = machine();
        let invite = write_invite(&machine, &producer());
        let instance = create(&machine.root, &invite, version(), None, None).unwrap();

        let mut settings = Table::new();
        settings.insert("default_hostility".into(), "Hostile".into());
        let config = instance.connector_config(settings).unwrap();
        assert_eq!(config["source_id"].as_str(), Some("radar-1"));
        assert_eq!(config["subject_prefix"].as_str(), Some("ajar.ingest"));
        assert_eq!(config["default_hostility"].as_str(), Some("Hostile"));
        assert_eq!(config["transport"]["kind"].as_str(), Some("tcp-client"));
        assert_eq!(
            config["signing_key_path"].as_str(),
            Some(instance.dir.join("signing.key").to_str().unwrap())
        );
    }

    #[test]
    fn settings_setting_an_invite_key_are_refused() {
        let machine = machine();
        let invite = write_invite(&machine, &producer());
        let instance = create(&machine.root, &invite, version(), None, None).unwrap();
        let mut settings = Table::new();
        settings.insert("nats_url".into(), "nats://elsewhere:4222".into());
        let err = instance.connector_config(settings).unwrap_err();
        assert!(err.to_string().contains("sets nats_url"), "{err}");
    }

    #[test]
    fn settings_set_only_the_local_transport_keys() {
        let machine = machine();
        let invite = write_invite(&machine, &producer());
        let instance = create(&machine.root, &invite, version(), None, None).unwrap();
        let local: Table = toml::from_str("[transport]\ninterface = \"10.1.2.3\"").unwrap();
        let config = instance.connector_config(local).unwrap();
        assert_eq!(config["transport"]["interface"].as_str(), Some("10.1.2.3"));
        assert_eq!(config["transport"]["kind"].as_str(), Some("tcp-client"));

        let moved: Table = toml::from_str("[transport]\nconnect = \"10.9.9.9:1\"").unwrap();
        let err = instance.connector_config(moved).unwrap_err();
        assert!(err.to_string().contains("transport.connect"), "{err}");
    }

    #[test]
    fn created_instance_loads_and_a_second_join_is_refused() {
        let machine = machine();
        let invite = write_invite(&machine, &producer());
        let created = create(&machine.root, &invite, version(), None, None).unwrap();
        let loaded = Instance::load_all(&machine.root).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].record, created.record);

        let err = create(&machine.root, &invite, version(), None, None).unwrap_err();
        assert!(err.to_string().contains("already exists"), "{err}");
        assert_eq!(Instance::load_all(&machine.root).unwrap().len(), 1);
    }

    #[test]
    fn consumer_without_a_target_is_refused_and_leaves_nothing() {
        let machine = machine();
        let consumer = Invite::Consumer(ConsumerInvite {
            connector_id: ConnectorId::try_from("ally-feed".to_owned()).unwrap(),
            connector_type: ConnectorType::try_from("adsb".to_owned()).unwrap(),
            nats_url: "tls://10.0.0.5:4222".into(),
            egress_subject: "ajar.egress.cot.*".into(),
        });
        let invite = write_invite(&machine, &consumer);
        let err = create(&machine.root, &invite, version(), None, None).unwrap_err();
        assert!(err.to_string().contains("none was given"), "{err}");
        let left = std::fs::read_dir(machine.root.instances_dir())
            .unwrap()
            .count();
        assert_eq!(left, 0);
    }

    #[test]
    fn connector_not_installed_names_install() {
        let machine = machine();
        let invite = write_invite(&machine, &producer());
        let missing = ConnectorVersion::try_from("0.6.6".to_owned()).unwrap();
        let err = create(&machine.root, &invite, missing, None, None).unwrap_err();
        assert!(err.to_string().contains("install adsb@0.6.6"), "{err}");
    }

    #[test]
    fn version_change_needs_that_version_installed() {
        let machine = machine();
        let invite = write_invite(&machine, &producer());
        let mut instance = create(&machine.root, &invite, version(), None, None).unwrap();

        let missing = ConnectorVersion::try_from("0.7.0".to_owned()).unwrap();
        assert!(instance.set_version(&machine.root, missing).is_err());
        assert_eq!(instance.record.version, version());

        let newer_dir = machine.root.connectors_dir().join("adsb/0.7.0");
        std::fs::create_dir_all(&newer_dir).unwrap();
        write_new(&newer_dir.join("ajar-adsb"), b"binary", 0o755).unwrap();
        let newer = ConnectorVersion::try_from("0.7.0".to_owned()).unwrap();
        instance.set_version(&machine.root, newer.clone()).unwrap();
        let loaded = Instance::load(&machine.root, instance.connector_id()).unwrap();
        assert_eq!(loaded.record.version, newer);
    }

    #[test]
    fn instance_without_a_pid_file_is_stopped() {
        let machine = machine();
        let invite = write_invite(&machine, &producer());
        let instance = create(&machine.root, &invite, version(), None, None).unwrap();
        assert_eq!(instance.state().unwrap(), ProcessState::Stopped);
        std::fs::write(instance.dir.join(PID_FILE), b"999999").unwrap();
        assert_eq!(instance.state().unwrap(), ProcessState::Died(999999));
    }

    /// Replaces the installed fake binary with a shell script running `body`.
    #[cfg(target_os = "linux")]
    fn install_script(machine: &crate::testutil::Machine, body: &str) {
        let binary = machine.root.connectors_dir().join("adsb/0.6.7/ajar-adsb");
        std::fs::write(binary, format!("#!/bin/sh\n{body}\n")).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn started_connector_runs_until_stopped() {
        let machine = machine();
        install_script(&machine, "while :; do sleep 0.1; done");
        let invite = write_invite(&machine, &producer());
        let instance = create(&machine.root, &invite, version(), None, None).unwrap();

        let pid = instance.start(&machine.root).unwrap();
        assert_eq!(instance.state().unwrap(), ProcessState::Running(pid));
        let err = instance.start(&machine.root).unwrap_err();
        assert!(err.to_string().contains("already running"), "{err}");

        instance.stop(false).unwrap();
        assert_eq!(instance.state().unwrap(), ProcessState::Stopped);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn connector_exiting_at_once_fails_the_start() {
        let machine = machine();
        install_script(&machine, "echo bad config >&2; exit 3");
        let invite = write_invite(&machine, &producer());
        let instance = create(&machine.root, &invite, version(), None, None).unwrap();
        let err = instance.start(&machine.root).unwrap_err();
        assert!(err.to_string().contains("exited at once"), "{err}");
        assert!(err.to_string().contains("bad config"), "{err}");
        assert_eq!(instance.state().unwrap(), ProcessState::Stopped);
    }
}
