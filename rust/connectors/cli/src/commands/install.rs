// SPDX-License-Identifier: Apache-2.0
//! `install`, `update`, `list` and `uninstall`: the connector types on this machine.

use std::collections::BTreeMap;

use ajar_tooling::invite::ConnectorType;
use ajar_tooling::prompt::{Plan, Prompt};
use ajar_tooling::releases::Platform;
use anyhow::Context as _;
use semver::Version;

use crate::connectors::{AvailableConnector, ConnectorVersion, InstallSource, Location, Overview};
use crate::context::Context;
use crate::instances::{Instance, ProcessState};

#[derive(Debug, clap::Args)]
pub struct InstallArgs {
    /// A connector type, optionally with a version: adsb or adsb@0.6.7.
    pub connector: String,
    /// Skip the confirmation.
    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, clap::Args)]
pub struct UpdateArgs {
    /// The connector type to update. Without it, every installed type is updated.
    pub connector: Option<String>,
    /// Move every instance on an older version to the new one, without asking.
    #[arg(long, conflicts_with = "keep_instances")]
    pub move_instances: bool,
    /// Leave every instance on its version, without asking.
    #[arg(long)]
    pub keep_instances: bool,
    /// Skip the confirmation.
    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, clap::Args)]
pub struct ListArgs {
    /// Also list the releases online.
    #[arg(long)]
    pub available: bool,
}

#[derive(Debug, clap::Args)]
pub struct UninstallArgs {
    /// The connector type and version: adsb@0.6.7, or adsb@local.
    pub connector: String,
    /// Skip the confirmation.
    #[arg(long)]
    pub yes: bool,
}

pub fn install(ctx: &Context, prompt: &mut Prompt, args: InstallArgs) -> anyhow::Result<()> {
    let root = ctx.root()?;
    let (connector_type, version) = parse_spec(&args.connector)?;
    let version = version
        .map(|v| Version::parse(&v).with_context(|| format!("{v:?} is not a version like 0.6.7")))
        .transpose()?;
    let mut overview = Overview::on_machine(root, &ctx.current_dir, Platform::current())?;

    let found = match overview.find_for_install(&connector_type, version.as_ref())? {
        InstallSource::AlreadyInstalled { installed, newer } => {
            prompt.say(&format!(
                "{connector_type} {} is already installed, so nothing changes.",
                installed.version
            ))?;
            if let Some(newer) = newer {
                prompt.say(&format!(
                    "{connector_type} {} is in packages/: `ajar-connectors update \
                     {connector_type}` installs it.",
                    newer.version
                ))?;
            }
            return Ok(());
        }
        InstallSource::Install(found) => found,
    };

    let mut plan = Plan::default();
    plan.add_step(install_step(&found));
    if !prompt.confirm(&plan, args.yes)? {
        prompt.say("Nothing was changed.")?;
        return Ok(());
    }
    let dir = crate::connectors::install(root, &found)?;
    prompt.say(&format!(
        "Installed {connector_type} {} in {}.",
        found.version,
        dir.display()
    ))?;
    prompt.say("Next: ajar-connectors join <invite>.")?;
    Ok(())
}

pub fn update(ctx: &Context, prompt: &mut Prompt, args: UpdateArgs) -> anyhow::Result<()> {
    let root = ctx.root()?;
    let mut overview = Overview::on_machine(root, &ctx.current_dir, Platform::current())?;
    let installed: Vec<AvailableConnector> = overview
        .on_machine_connectors()
        .iter()
        .filter(|c| matches!(c.location, Location::Installed(_)))
        .cloned()
        .collect();
    let types: Vec<ConnectorType> = match &args.connector {
        Some(text) => {
            let (connector_type, version) = parse_spec(text)?;
            if version.is_some() {
                anyhow::bail!(
                    "update installs the newest version: name the type only, as {connector_type}"
                );
            }
            if !installed.iter().any(|c| c.connector_type == connector_type) {
                anyhow::bail!(
                    "{connector_type} is not installed: `ajar-connectors install {connector_type}`"
                );
            }
            vec![connector_type]
        }
        None => {
            let mut types: Vec<ConnectorType> =
                installed.iter().map(|c| c.connector_type.clone()).collect();
            types.dedup();
            types
        }
    };
    if types.is_empty() {
        prompt.say("No connector is installed, so there is nothing to update.")?;
        return Ok(());
    }

    let online = match overview.online() {
        Ok(online) => online.to_vec(),
        Err(reason) => {
            let reason = reason.to_owned();
            prompt.warn(&format!(
                "online releases are unavailable, so only packages/ is looked at: {reason}"
            ))?;
            Vec::new()
        }
    };
    let mut updates = Vec::new();
    for connector_type in &types {
        let newest_installed = installed
            .iter()
            .filter(|c| &c.connector_type == connector_type)
            .map(|c| &c.version)
            .max();
        let candidates = overview
            .on_machine_connectors()
            .iter()
            .chain(&online)
            .filter(|c| &c.connector_type == connector_type)
            .filter(|c| matches!(c.location, Location::Package(_) | Location::Online(_)));
        // A package wins over the same version online: it needs no network.
        let newest = candidates.max_by(|a, b| {
            a.version.cmp(&b.version).then(
                matches!(a.location, Location::Package(_))
                    .cmp(&matches!(b.location, Location::Package(_))),
            )
        });
        match newest {
            Some(newest) if Some(&newest.version) > newest_installed => {
                updates.push(newest.clone())
            }
            _ => prompt.say(&format!("{connector_type} is up to date."))?,
        }
    }
    if updates.is_empty() {
        return Ok(());
    }

    let instances = Instance::load_all(root)?;
    let mut plan = Plan::default();
    for update in &updates {
        plan.add_step(install_step(update));
    }
    // Each type has at most one update, so an instance is behind at most one of them.
    let behind = instances.iter().filter_map(|instance| {
        let update = updates
            .iter()
            .find(|u| &u.connector_type == instance.record.invite.connector_type())?;
        // A local binary has no version to compare, so its instances stay on it.
        let behind = matches!(instance.record.version, ConnectorVersion::Release(_))
            && instance.record.version < update.version;
        behind.then_some((instance, update))
    });
    let mut moves = Vec::new();
    for (instance, update) in behind {
        let question = format!(
            "Move {} from {} to {}?",
            instance.connector_id(),
            instance.record.version,
            update.version
        );
        let move_it = if args.move_instances {
            true
        } else if args.keep_instances || !prompt.is_interactive() {
            false
        } else {
            prompt.ask_yes_no(&question, "--move-instances", false)?
        };
        if move_it {
            plan.add_step(format!(
                "move {} from {} to {}, restarting it if it runs",
                instance.connector_id(),
                instance.record.version,
                update.version
            ));
            moves.push((instance.connector_id().clone(), update.version.clone()));
        } else {
            plan.add_step(format!(
                "keep {} on {}; `ajar-connectors start {} --version {}` moves it later",
                instance.connector_id(),
                instance.record.version,
                instance.connector_id(),
                update.version
            ));
        }
    }
    if !prompt.confirm(&plan, args.yes)? {
        prompt.say("Nothing was changed.")?;
        return Ok(());
    }

    for update in &updates {
        let dir = crate::connectors::install(root, update)?;
        prompt.say(&format!(
            "Installed {} {} in {}.",
            update.connector_type,
            update.version,
            dir.display()
        ))?;
    }
    let mut not_started = Vec::new();
    for (connector_id, version) in moves {
        let mut instance = Instance::load(root, &connector_id)?;
        let old_version = instance.record.version.clone();
        let was_running = matches!(instance.state()?, ProcessState::Running(_));
        if was_running {
            instance.stop(false)?;
        }
        instance.set_version(root, version.clone())?;
        if !was_running {
            prompt.say(&format!("Moved {connector_id} to {version}."))?;
            continue;
        }
        match instance.start(root) {
            Ok(pid) => prompt.say(&format!(
                "Moved {connector_id} to {version}; running as pid {pid}."
            ))?,
            Err(e) => {
                prompt.warn(&format!(
                    "{connector_id} moved to {version} but did not start, so it is stopped: \
                     {e:#}\nTo go back: ajar-connectors start {connector_id} --version \
                     {old_version}"
                ))?;
                not_started.push(connector_id.to_string());
            }
        }
    }
    if !not_started.is_empty() {
        anyhow::bail!("not running after the move: {}", not_started.join(", "));
    }
    Ok(())
}

pub fn list(ctx: &Context, prompt: &mut Prompt, args: ListArgs) -> anyhow::Result<()> {
    let Ok(root) = ctx.root() else {
        if !args.available {
            ctx.root()?;
        }
        let platform = Platform::current().with_context(|| {
            format!(
                "no connectors are released for {} on {}",
                std::env::consts::OS,
                std::env::consts::ARCH
            )
        })?;
        // Sorted by type then version, so the last version of each type is its newest.
        let newest: BTreeMap<ConnectorType, Version> =
            ajar_tooling::releases::list_online(platform)?
                .into_iter()
                .map(|release| (release.tarball.connector_type, release.tarball.version))
                .collect();
        prompt.say("Online, newest version of each:")?;
        for (connector_type, version) in newest {
            prompt.say(&format!("  {connector_type} {version}"))?;
        }
        prompt.say("Older versions install with ajar-connectors install <connector>@<version>.")?;
        return Ok(());
    };

    let mut overview = Overview::on_machine(root, &ctx.current_dir, Platform::current())?;
    let instances = Instance::load_all(root)?;
    if overview.on_machine_connectors().is_empty() && overview.unusable.is_empty() {
        prompt.say("No connector is installed, in packages/ or in the current folder.")?;
    }
    // The overview lists installed connectors first, then packages, then binary files.
    let mut heading = None;
    for connector in overview.on_machine_connectors() {
        let this_heading = match connector.location {
            Location::Installed(_) => "Installed:",
            Location::Package(_) => "In packages/:",
            Location::BinaryFile(_) => "In the current folder:",
            Location::Online(_) => "Online:",
        };
        if heading != Some(this_heading) {
            prompt.say(this_heading)?;
            heading = Some(this_heading);
        }
        let users: Vec<String> = instances
            .iter()
            .filter(|i| {
                matches!(connector.location, Location::Installed(_))
                    && i.record.invite.connector_type() == &connector.connector_type
                    && i.record.version == connector.version
            })
            .map(|i| i.connector_id().to_string())
            .collect();
        let used_by = match users.is_empty() {
            true => String::new(),
            false => format!(" (used by {})", users.join(", ")),
        };
        prompt.say(&format!(
            "  {} {}{used_by}",
            connector.connector_type, connector.version
        ))?;
    }
    if args.available {
        match overview.online() {
            Ok(online) => {
                // Sorted by type then version, so the last version of each type is its newest.
                let newest: BTreeMap<ConnectorType, ConnectorVersion> = online
                    .iter()
                    .map(|c| (c.connector_type.clone(), c.version.clone()))
                    .collect();
                prompt.say("Online, newest version of each:")?;
                for (connector_type, version) in newest {
                    prompt.say(&format!("  {connector_type} {version}"))?;
                }
                prompt.say(
                    "Older versions install with ajar-connectors install <connector>@<version>.",
                )?;
            }
            Err(reason) => {
                let reason = reason.to_owned();
                prompt.say(&format!("Online: unavailable, {reason}"))?;
            }
        }
    }
    if !overview.unusable.is_empty() {
        prompt.say("Can't be installed:")?;
        for (path, reason) in &overview.unusable {
            prompt.say(&format!("  {}: {reason}", path.display()))?;
        }
    }
    Ok(())
}

pub fn uninstall(ctx: &Context, prompt: &mut Prompt, args: UninstallArgs) -> anyhow::Result<()> {
    let root = ctx.root()?;
    let (connector_type, version) = parse_spec(&args.connector)?;
    let version = version
        .with_context(|| format!("name the version to uninstall, as {connector_type}@<version>"))?;
    let version = ConnectorVersion::try_from(version)?;
    let dir = root
        .connectors_dir()
        .join(connector_type.as_str())
        .join(version.to_string());
    if !dir.is_dir() {
        anyhow::bail!("{connector_type} {version} is not installed");
    }
    let users: Vec<String> = Instance::load_all(root)?
        .iter()
        .filter(|i| {
            i.record.invite.connector_type() == &connector_type && i.record.version == version
        })
        .map(|i| i.connector_id().to_string())
        .collect();
    if !users.is_empty() {
        anyhow::bail!(
            "{connector_type} {version} is used by {}: move each to another installed version \
             (`ajar-connectors stop <connector-id>`, then `ajar-connectors start <connector-id> \
             --version <version>`), or remove it first",
            users.join(", ")
        );
    }

    let mut plan = Plan::default();
    plan.add_step(format!("remove {}", dir.display()));
    if !prompt.confirm(&plan, args.yes)? {
        prompt.say("Nothing was changed.")?;
        return Ok(());
    }
    crate::connectors::uninstall(&dir)?;
    prompt.say(&format!("Uninstalled {connector_type} {version}."))?;
    Ok(())
}

/// `adsb` or `adsb@0.6.7`, split into the type and the version text.
pub(crate) fn parse_spec(text: &str) -> anyhow::Result<(ConnectorType, Option<String>)> {
    let (name, version) = match text.split_once('@') {
        Some((name, version)) => (name, Some(version.to_owned())),
        None => (text, None),
    };
    let connector_type = ConnectorType::try_from(name.to_owned())?;
    Ok((connector_type, version))
}

fn install_step(connector: &AvailableConnector) -> String {
    let source = match &connector.location {
        Location::Installed(dir) => format!("already in {}", dir.display()),
        Location::Package(path) => format!("from {}", path.display()),
        Location::BinaryFile(path) => format!("from {}, as version local", path.display()),
        Location::Online(release) => format!("from GitHub ({})", release.tarball),
    };
    format!(
        "install {} {} {source}",
        connector.connector_type, connector.version
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{create, machine, producer, write_invite, Machine};

    #[test]
    fn version_in_use_is_kept_and_an_unused_one_uninstalled() {
        let machine = machine();
        let invite = write_invite(&machine, &producer());
        let version = ConnectorVersion::try_from("0.6.7".to_owned()).unwrap();
        create(&machine.root, &invite, version, None, None).unwrap();
        let unused = machine.root.connectors_dir().join("adsb/0.7.0");
        std::fs::create_dir_all(&unused).unwrap();
        std::fs::write(unused.join("ajar-adsb"), b"binary").unwrap();
        let Machine { tmp, root } = machine;
        let ctx = Context::in_root(root, tmp.path().to_path_buf());
        let uninstall_args = |connector: &str| UninstallArgs {
            connector: connector.into(),
            yes: true,
        };

        let err =
            uninstall(&ctx, &mut Prompt::terminal(), uninstall_args("adsb@0.6.7")).unwrap_err();
        assert!(err.to_string().contains("used by radar-1"), "{err}");
        let in_use = ctx.root().unwrap().connectors_dir().join("adsb/0.6.7");
        assert!(in_use.is_dir());

        uninstall(&ctx, &mut Prompt::terminal(), uninstall_args("adsb@0.7.0")).unwrap();
        assert!(!unused.exists());
    }
}
