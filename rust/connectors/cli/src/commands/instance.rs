// SPDX-License-Identifier: Apache-2.0
//! The commands on instances and their connectors: `run`, `start`, `stop`, `status`, `logs`,
//! `check` and `remove`.

use std::fs::File;
use std::io::{ErrorKind, Read, Seek, SeekFrom};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use ajar_doctor::report::Status;
use ajar_tooling::invite::{ConnectorId, Invite};
use ajar_tooling::prompt::{Plan, Prompt};
use ajar_tooling::releases::Platform;
use anyhow::Context as _;

use crate::connectors::{ConnectorVersion, Location, Overview};
use crate::context::Context;
use crate::instances::{Instance, ProcessState};

#[derive(Debug, clap::Args)]
pub struct RunArgs {
    /// An installed connector type, optionally with a version: adsb or adsb@0.6.7.
    pub connector: String,
    /// The connector's config file.
    pub config: PathBuf,
}

#[derive(Debug, clap::Args)]
pub struct StartArgs {
    pub connector_id: String,
    /// Move the instance to this installed version first.
    #[arg(long)]
    pub version: Option<String>,
    /// Change where a consumer delivers first.
    #[arg(long)]
    pub target: Option<String>,
}

#[derive(Debug, clap::Args)]
pub struct StopArgs {
    pub connector_id: String,
    /// Kill the connector instead of asking it to stop.
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, clap::Args)]
pub struct LogsArgs {
    pub connector_id: String,
    /// The number of lines to show.
    #[arg(long, default_value_t = 50)]
    pub lines: usize,
    /// Keep showing lines as the connector writes them.
    #[arg(long)]
    pub follow: bool,
}

#[derive(Debug, clap::Args)]
pub struct CheckArgs {
    /// The instance to check.
    #[arg(required_unless_present = "config", conflicts_with = "config")]
    pub connector_id: Option<String>,
    /// A connector config to check instead, with the AJAR_TLS_* environment.
    #[arg(long)]
    pub config: Option<PathBuf>,
    /// The connector ID of a consumer config given with --config.
    #[arg(long, requires = "config")]
    pub consumer: Option<String>,
}

#[derive(Debug, clap::Args)]
pub struct RemoveArgs {
    pub connector_id: String,
    /// Skip the confirmation.
    #[arg(long)]
    pub yes: bool,
}

/// Runs an installed connector in the foreground with `config`, as this process.
pub fn run(ctx: &Context, args: RunArgs) -> anyhow::Result<()> {
    let root = ctx.root()?;
    let (connector_type, version) = super::install::parse_spec(&args.connector)?;
    let installed = Overview::on_machine(root, Platform::current())?
        .on_machine_connectors()
        .iter()
        .filter(|c| c.connector_type == connector_type)
        .filter_map(|c| match &c.location {
            Location::Installed(dir) => Some((c.version.clone(), dir.clone())),
            _ => None,
        })
        .collect::<Vec<_>>();
    let (_, dir) = match version {
        Some(text) => {
            let version = ConnectorVersion::try_from(text)?;
            installed
                .into_iter()
                .find(|(v, _)| *v == version)
                .with_context(|| format!("{connector_type} {version} is not installed"))?
        }
        None => installed.into_iter().max_by(|a, b| a.0.cmp(&b.0)).with_context(|| {
            format!("{connector_type} is not installed: run `ajar-connectors install {connector_type}`")
        })?,
    };
    let binary = crate::connectors::installed_binary(&dir)?;
    // exec only returns when the binary could not be started.
    let error = Command::new(&binary).arg(&args.config).exec();
    Err(error).with_context(|| format!("running {}", binary.display()))
}

pub fn start(ctx: &Context, prompt: &mut Prompt, args: StartArgs) -> anyhow::Result<()> {
    let root = ctx.root()?;
    let mut instance = Instance::load(root, &ConnectorId::try_from(args.connector_id)?)?;
    let connector_id = instance.connector_id().clone();
    if let ProcessState::Running(pid) = instance.state()? {
        anyhow::bail!("{connector_id} is already running as pid {pid}");
    }
    if args.target.is_some() && matches!(instance.record.invite, Invite::Producer(_)) {
        anyhow::bail!("{connector_id} is a producer, which has no target");
    }
    if let Some(text) = args.version {
        let version = ConnectorVersion::try_from(text)?;
        instance.set_version(root, version.clone())?;
        prompt.say(&format!("{connector_id} now runs {version}."))?;
    }
    if let Some(target) = args.target {
        instance.set_target(target.clone())?;
        prompt.say(&format!("{connector_id} now delivers to {target}."))?;
    }
    let pid = instance.start(root)?;
    prompt.say(&format!("{connector_id} is running as pid {pid}."))?;
    Ok(())
}

pub fn stop(ctx: &Context, prompt: &mut Prompt, args: StopArgs) -> anyhow::Result<()> {
    let root = ctx.root()?;
    let instance = Instance::load(root, &ConnectorId::try_from(args.connector_id)?)?;
    let connector_id = instance.connector_id();
    let state = instance.state()?;
    instance.stop(args.force)?;
    match state {
        ProcessState::Died(pid) => prompt.say(&format!(
            "{connector_id} was not running any more (was pid {pid}): `ajar-connectors logs \
             {connector_id}` shows why"
        ))?,
        _ => prompt.say(&format!("{connector_id} is stopped."))?,
    }
    Ok(())
}

pub fn status(ctx: &Context, prompt: &mut Prompt) -> anyhow::Result<()> {
    let root = ctx.root()?;
    let instances = Instance::load_all(root)?;
    if instances.is_empty() {
        prompt.say("No instances yet: ajar-connectors join <invite> creates one.")?;
        return Ok(());
    }
    for instance in &instances {
        let state = match instance.state()? {
            ProcessState::Running(pid) => format!("running as pid {pid}"),
            ProcessState::Stopped => "stopped".to_owned(),
            ProcessState::Died(pid) => format!(
                "not running (was pid {pid}; it exited, or the machine restarted): see \
                 ajar-connectors logs {}",
                instance.connector_id()
            ),
        };
        let target = match &instance.record.target {
            Some(target) => format!(", delivers to {target}"),
            None => String::new(),
        };
        prompt.say(&format!(
            "{}: {} {}{target}, {state}",
            instance.connector_id(),
            instance.record.invite.connector_type(),
            instance.record.version
        ))?;
    }
    Ok(())
}

pub fn logs(ctx: &Context, prompt: &mut Prompt, args: LogsArgs) -> anyhow::Result<()> {
    const TAIL_BYTES: u64 = 256 * 1024;
    let root = ctx.root()?;
    let instance = Instance::load(root, &ConnectorId::try_from(args.connector_id)?)?;
    let path = instance.log_path();
    let mut file = match File::open(&path) {
        Ok(file) => file,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            anyhow::bail!(
                "{} has no log yet: it has never been started",
                instance.connector_id()
            )
        }
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let end = file.metadata()?.len();
    file.seek(SeekFrom::Start(end.saturating_sub(TAIL_BYTES)))?;
    // Read as bytes: the tail can start inside a multi-byte character.
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .with_context(|| format!("reading {}", path.display()))?;
    let text = String::from_utf8_lossy(&bytes);
    let lines: Vec<&str> = text.lines().collect();
    for line in &lines[lines.len().saturating_sub(args.lines)..] {
        prompt.say(line)?;
    }

    if !args.follow {
        return Ok(());
    }
    let mut partial = Vec::new();
    loop {
        std::thread::sleep(Duration::from_millis(500));
        file.read_to_end(&mut partial)
            .with_context(|| format!("reading {}", path.display()))?;
        while let Some(end) = partial.iter().position(|byte| *byte == b'\n') {
            let line: Vec<u8> = partial.drain(..=end).collect();
            prompt.say(String::from_utf8_lossy(&line).trim_end())?;
        }
    }
}

pub fn check(ctx: &Context, prompt: &mut Prompt, args: CheckArgs) -> anyhow::Result<()> {
    let findings = match (args.connector_id, args.config) {
        (Some(connector_id), _) => {
            let root = ctx.root()?;
            Instance::load(root, &ConnectorId::try_from(connector_id)?)?.preflight()?
        }
        (None, Some(config)) => {
            let options = ajar_doctor::Options {
                role: match args.consumer {
                    Some(connector_id) => ajar_doctor::Role::Consumer { connector_id },
                    None => ajar_doctor::Role::Producer,
                },
                config_path: config.to_string_lossy().into_owned(),
                tls_files: None,
                timeout: Duration::from_secs(5),
            };
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("starting the check")?;
            runtime.block_on(ajar_doctor::run(&options))
        }
        (None, None) => anyhow::bail!("name an instance, or a config with --config"),
    };
    let (report, _) = ajar_doctor::report::render(&findings);
    prompt.say(report.trim_end())?;
    let failed: Vec<&str> = findings
        .iter()
        .filter(|f| f.status == Status::Fail)
        .map(|f| f.step)
        .collect();
    if !failed.is_empty() {
        anyhow::bail!("the check failed at {}", failed.join(", "));
    }
    Ok(())
}

pub fn remove(ctx: &Context, prompt: &mut Prompt, args: RemoveArgs) -> anyhow::Result<()> {
    let root = ctx.root()?;
    let connector_id = ConnectorId::try_from(args.connector_id)?;
    let instance = Instance::load(root, &connector_id)?;
    if let ProcessState::Running(pid) = instance.state()? {
        anyhow::bail!(
            "{connector_id} is running as pid {pid}: `ajar-connectors stop {connector_id}` first"
        );
    }
    let mut plan = Plan::default();
    plan.add_step(format!(
        "remove {} with its keys, settings and log; Core still knows {connector_id} until the \
         operator revokes it",
        root.instance_dir(&connector_id).display()
    ));
    if !prompt.confirm(&plan, args.yes)? {
        prompt.say("Nothing was changed.")?;
        return Ok(());
    }
    instance.remove()?;
    prompt.say(&format!("Removed {connector_id}."))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{create, machine, producer, write_invite, Machine};

    #[test]
    fn producer_given_a_target_keeps_its_version() {
        let machine = machine();
        let invite = write_invite(&machine, &producer());
        let version = ConnectorVersion::try_from("0.6.7".to_owned()).unwrap();
        create(&machine.root, &invite, version.clone(), None, None).unwrap();
        let newer = machine.root.connectors_dir().join("adsb/0.7.0");
        std::fs::create_dir_all(&newer).unwrap();
        std::fs::write(newer.join("ajar-adsb"), b"binary").unwrap();
        let Machine { tmp, root } = machine;
        let ctx = Context::in_root(root, tmp.path().to_path_buf());

        let args = StartArgs {
            connector_id: "radar-1".into(),
            version: Some("0.7.0".into()),
            target: Some("tls://tak:8089".into()),
        };
        let err = start(&ctx, &mut Prompt::terminal(), args).unwrap_err();
        assert!(err.to_string().contains("no target"), "{err}");
        let instance = Instance::load(ctx.root().unwrap(), producer().connector_id()).unwrap();
        assert_eq!(instance.record.version, version);
    }
}
