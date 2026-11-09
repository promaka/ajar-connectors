// SPDX-License-Identifier: Apache-2.0
//! `join` enrols a connector on this machine from an invite: check the invite, check the
//! machine, run the preflight, show the plan, then create and start the instance. `request`
//! makes the keys for an invite that should carry none.

use std::path::PathBuf;

use ajar_doctor::report::Status;
use ajar_tooling::invite::{ConnectorId, ConnectorType, Invite};
use ajar_tooling::prompt::{MenuOption, Plan, Prompt};
use ajar_tooling::releases::Platform;
use ajar_tooling::request::Role;
use anyhow::Context as _;

use crate::connectors::{ConnectorVersion, Location, Overview};
use crate::context::Context;
use crate::instances::StagedInstance;

#[derive(Debug, clap::Args)]
pub struct JoinArgs {
    /// The invite file from the operator.
    pub invite: PathBuf,
    /// Check the invite, this machine and the connection, and change nothing.
    #[arg(long)]
    pub check: bool,
    /// Create the instance without starting it. Failed network checks don't stop the join then.
    #[arg(long)]
    pub no_start: bool,
    /// The installed version to run. Without it, the newest installed version.
    #[arg(long)]
    pub version: Option<String>,
    /// The egress connector's delivery target, such as tls://takserver:8089.
    #[arg(long)]
    pub target: Option<String>,
    /// A settings.toml to copy into the instance.
    #[arg(long)]
    pub settings: Option<PathBuf>,
    /// Delete the invite file after joining, without asking.
    #[arg(long)]
    pub delete_invite: bool,
    /// Skip the confirmation.
    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, clap::Args)]
pub struct RequestArgs {
    /// The connector type, such as adsb.
    pub connector: String,
    /// The connector ID to ask the operator for, such as radar-1.
    pub connector_id: String,
    /// The connector's role: it publishes events or reads Core's egress. Without it, request asks.
    #[arg(long, value_enum)]
    pub role: Option<RoleArg>,
    /// Skip the confirmation.
    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum RoleArg {
    Producer,
    Consumer,
}

pub fn join(ctx: &Context, prompt: &mut Prompt, args: JoinArgs) -> anyhow::Result<()> {
    // Doctor steps that need the network. `--no-start` lets the join go ahead when only these
    // fail.
    const NETWORK_STEPS: [&str; 4] = ["endpoint", "tls handshake", "clock", "target"];
    let root = ctx.root()?;
    let mut staged = StagedInstance::stage(root, &args.invite)?;
    let invite = staged.invite().clone();
    let connector_id = invite.connector_id();
    let connector_type = invite.connector_type();
    prompt.say(&format!(
        "{} is intact: it enrols {connector_id} ({connector_type}).",
        args.invite.display()
    ))?;

    let version = match &args.version {
        Some(text) => ConnectorVersion::try_from(text.clone())?,
        None => Overview::on_machine(root, &ctx.current_dir, Platform::current())?
            .on_machine_connectors()
            .iter()
            .filter(|c| &c.connector_type == connector_type)
            .filter(|c| matches!(c.location, Location::Installed(_)))
            .map(|c| c.version.clone())
            .max()
            .with_context(|| {
                format!(
                    "{connector_type} is not installed: run `ajar-connectors install \
                     {connector_type}`, then join again"
                )
            })?,
    };
    let target = match (&invite, args.target) {
        (Invite::Consumer(_), None) => Some(prompt.ask(
            &format!("Where does {connector_id} deliver to (a URL or host:port)"),
            "--target",
            None,
        )?),
        (_, target) => target,
    };
    let instance = staged.prepare(root, version.clone(), target, args.settings.as_deref())?;

    let findings = instance.preflight()?;
    let (report, _) = ajar_doctor::report::render(&findings);
    prompt.say(report.trim_end())?;
    let failed: Vec<&str> = findings
        .iter()
        .filter(|f| f.status == Status::Fail)
        .map(|f| f.step)
        .collect();
    let blocking: Vec<&str> = failed
        .iter()
        .copied()
        .filter(|step| !(args.no_start && NETWORK_STEPS.contains(step)))
        .collect();
    if args.check {
        prompt.say("Checked only: nothing was changed.")?;
        if !failed.is_empty() {
            anyhow::bail!("the preflight failed at {}", failed.join(", "));
        }
        return Ok(());
    }
    if !blocking.is_empty() {
        let network_only = blocking.iter().all(|step| NETWORK_STEPS.contains(step));
        let way_out = match network_only {
            true => ", or join with --no-start to create the instance without starting it",
            false => "",
        };
        anyhow::bail!(
            "the preflight failed at {}: fix the first FAIL above{way_out}",
            blocking.join(", ")
        );
    }

    let mut plan = Plan::default();
    plan.add_step(format!(
        "create instance {connector_id} for {connector_type} {version} in {}",
        staged.dir().display()
    ));
    if !staged.invite_held_keys() {
        plan.add_step(format!(
            "move the keys from this machine's request for {connector_id} into it"
        ));
    }
    if !args.no_start {
        plan.add_step(format!("start {connector_id}"));
    }
    if args.delete_invite {
        plan.add_step(format!("delete {}", args.invite.display()));
    }
    if !prompt.confirm(&plan, args.yes)? {
        prompt.say("Nothing was changed.")?;
        return Ok(());
    }
    let invite_held_keys = staged.invite_held_keys();
    let instance = staged.commit()?;
    prompt.say(&format!("Created instance {connector_id}."))?;
    let mut start_failed = false;
    if !args.no_start {
        match instance.start(root) {
            Ok(pid) => prompt.say(&format!("{connector_id} is running as pid {pid}."))?,
            Err(e) => {
                start_failed = true;
                prompt.warn(&format!(
                    "{connector_id} was created but did not start: {e:#}\n\
                     See `ajar-connectors logs {connector_id}`, then `ajar-connectors start \
                     {connector_id}`."
                ))?;
            }
        }
    }

    if args.delete_invite {
        std::fs::remove_file(&args.invite)
            .with_context(|| format!("deleting {}", args.invite.display()))?;
        prompt.say(&format!("Deleted {}.", args.invite.display()))?;
    } else if invite_held_keys {
        prompt.say(&format!(
            "{} holds {connector_id}'s private keys, which are now in the instance. Anyone who \
             has the file can connect as {connector_id}.",
            args.invite.display()
        ))?;
        let question = format!("Delete {}?", args.invite.display());
        if prompt.is_interactive() && prompt.ask_yes_no(&question, "--delete-invite", false)? {
            std::fs::remove_file(&args.invite)
                .with_context(|| format!("deleting {}", args.invite.display()))?;
            prompt.say(&format!("Deleted {}.", args.invite.display()))?;
        } else {
            prompt.warn(&format!(
                "{} is kept: delete it, or keep it somewhere only you can read",
                args.invite.display()
            ))?;
        }
    }
    if start_failed {
        anyhow::bail!("{connector_id} was created but is not running");
    }
    Ok(())
}

pub fn request(ctx: &Context, prompt: &mut Prompt, args: RequestArgs) -> anyhow::Result<()> {
    let root = ctx.root()?;
    let connector_type = ConnectorType::try_from(args.connector)?;
    let connector_id = ConnectorId::try_from(args.connector_id)?;
    let role = match args.role {
        Some(RoleArg::Producer) => Role::Producer,
        Some(RoleArg::Consumer) => Role::Consumer,
        None => {
            let options = [
                MenuOption::available("producer: publishes events to Core", Role::Producer),
                MenuOption::available("consumer: reads Core's egress", Role::Consumer),
            ];
            *prompt.choose(&format!("What does {connector_id} do?"), "--role", &options)?
        }
    };
    let request_path = ctx.current_dir.join(format!("{connector_id}.request"));
    if request_path.exists() {
        anyhow::bail!("{} already exists", request_path.display());
    }
    if root.instance_dir(&connector_id).exists() {
        anyhow::bail!("instance {connector_id} already exists on this machine");
    }
    let keys_dir = root.requests_dir().join(connector_id.as_str());
    if keys_dir.exists() {
        anyhow::bail!(
            "a request for {connector_id} was already made here, and its keys wait in {}: join \
             the invite that answers it, or delete that folder to make a new request",
            keys_dir.display()
        );
    }

    let mut plan = Plan::default();
    plan.add_step(format!(
        "create {connector_id}'s private keys in {}",
        keys_dir.display()
    ));
    plan.add_step(format!(
        "write {} with their public halves",
        request_path.display()
    ));
    if !prompt.confirm(&plan, args.yes)? {
        prompt.say("Nothing was changed.")?;
        return Ok(());
    }
    let (request, keys) =
        ajar_tooling::request::create(role, connector_id.clone(), connector_type)?;
    let keys_dir = crate::instances::store_request_keys(root, &connector_id, &keys)?;
    if let Err(e) = ajar_tooling::request::write(&request, &request_path) {
        let _ = std::fs::remove_dir_all(&keys_dir);
        return Err(e.into());
    }
    prompt.say(&format!(
        "Wrote {}. Send it to your operator: their invite will hold no private keys, and joins \
         only on this machine.",
        request_path.display()
    ))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{machine, producer, request_keys, write_answer, Machine};

    /// A producer whose bus nothing listens on, so the preflight's network steps fail.
    fn on_a_closed_bus() -> Invite {
        let mut invite = producer();
        if let Invite::Producer(p) = &mut invite {
            p.nats_url = "tls://127.0.0.1:1".into();
            p.transport = serde_json::json!({"kind": "udp", "bind": "127.0.0.1:0"})
                .as_object()
                .unwrap()
                .clone();
        }
        invite
    }

    fn join_args(invite: PathBuf, no_start: bool) -> JoinArgs {
        JoinArgs {
            invite,
            check: false,
            no_start,
            version: None,
            target: None,
            settings: None,
            delete_invite: true,
            yes: true,
        }
    }

    #[test]
    fn answer_joins_without_start_and_its_invite_is_deleted() {
        let machine = machine();
        let keys = request_keys(&machine);
        let invite = write_answer(&machine, &on_a_closed_bus(), &keys.mtls_key_pem);
        let Machine { tmp, root } = machine;
        let ctx = Context::in_root(root, tmp.path().to_path_buf());

        join(
            &ctx,
            &mut Prompt::terminal(),
            join_args(invite.clone(), true),
        )
        .unwrap();
        let root = ctx.root().unwrap();
        let connector_id = producer().connector_id().clone();
        assert!(root
            .instance_dir(&connector_id)
            .join("instance.toml")
            .is_file());
        assert!(!root.requests_dir().join(connector_id.as_str()).exists());
        assert!(
            !invite.exists(),
            "--delete-invite holds for an invite without keys"
        );
    }

    #[test]
    fn failed_network_check_stops_the_join_before_anything_changes() {
        let machine = machine();
        let keys = request_keys(&machine);
        let invite = write_answer(&machine, &on_a_closed_bus(), &keys.mtls_key_pem);
        let Machine { tmp, root } = machine;
        let ctx = Context::in_root(root, tmp.path().to_path_buf());

        let err = join(
            &ctx,
            &mut Prompt::terminal(),
            join_args(invite.clone(), false),
        )
        .unwrap_err();
        assert!(err.to_string().contains("--no-start"), "{err}");
        let root = ctx.root().unwrap();
        let connector_id = producer().connector_id().clone();
        assert!(!root.instance_dir(&connector_id).exists());
        assert!(root.requests_dir().join(connector_id.as_str()).exists());
        assert!(invite.exists());
    }
}
