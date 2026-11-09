// SPDX-License-Identifier: Apache-2.0
//! `ajar-connectors`: installs, enrols and runs Ajar connectors on this machine.

mod commands;
mod connectors;
mod context;
mod instances;
#[cfg(test)]
mod testutil;

use std::process::ExitCode;

use ajar_tooling::prompt::Prompt;
use clap::{Parser, Subcommand};

use crate::commands::{install, instance, join, setup};
use crate::context::Context;

#[derive(Parser)]
#[command(
    name = "ajar-connectors",
    version,
    about = "Installs, enrols and runs Ajar connectors on this machine."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create the folder ajar-connectors lives in, and put it on the PATH.
    Setup(setup::SetupArgs),
    /// Install a connector type from a package, a binary file or an online release.
    Install(install::InstallArgs),
    /// Install newer versions, and move instances onto them.
    Update(install::UpdateArgs),
    /// List the connector types on this machine, and online with --available.
    List(install::ListArgs),
    /// Remove an installed version that no instance uses.
    Uninstall(install::UninstallArgs),
    /// Enrol a connector from the operator's invite, and start it.
    Join(join::JoinArgs),
    /// Make the keys for a connector, and the request file for the operator.
    Request(join::RequestArgs),
    /// Run an installed connector in the foreground with a config file.
    Run(instance::RunArgs),
    /// Start an instance.
    Start(instance::StartArgs),
    /// Stop an instance.
    Stop(instance::StopArgs),
    /// Show every instance and whether it runs.
    Status,
    /// Show an instance's log.
    Logs(instance::LogsArgs),
    /// Check an instance, or a config, can connect: the preflight join runs.
    Check(instance::CheckArgs),
    /// Remove a stopped instance with its keys.
    Remove(instance::RemoveArgs),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = Context::load().and_then(|ctx| {
        let mut prompt = Prompt::terminal();
        match cli.command {
            Command::Setup(args) => setup::run(&ctx, &mut prompt, args),
            Command::Install(args) => install::install(&ctx, &mut prompt, args),
            Command::Update(args) => install::update(&ctx, &mut prompt, args),
            Command::List(args) => install::list(&ctx, &mut prompt, args),
            Command::Uninstall(args) => install::uninstall(&ctx, &mut prompt, args),
            Command::Join(args) => join::join(&ctx, &mut prompt, args),
            Command::Request(args) => join::request(&ctx, &mut prompt, args),
            Command::Run(args) => instance::run(&ctx, args),
            Command::Start(args) => instance::start(&ctx, &mut prompt, args),
            Command::Stop(args) => instance::stop(&ctx, &mut prompt, args),
            Command::Status => instance::status(&ctx, &mut prompt),
            Command::Logs(args) => instance::logs(&ctx, &mut prompt, args),
            Command::Check(args) => instance::check(&ctx, &mut prompt, args),
            Command::Remove(args) => instance::remove(&ctx, &mut prompt, args),
        }
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}
