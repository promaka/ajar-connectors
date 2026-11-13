// SPDX-License-Identifier: Apache-2.0
//! `ajar-connectors setup`: creates the root folder, copies this binary into its `bin/`, copies
//! the packages a package tar carries, and puts the command on the PATH.

use std::fs::Permissions;
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use ajar_tooling::prompt::{MenuOption, Plan, Prompt};
use ajar_tooling::releases::TarballName;
use anyhow::Context as _;

use crate::context::{Context, Root, Scope};

#[derive(Debug, clap::Args)]
pub struct SetupArgs {
    /// The root folder to create. Without it, setup asks.
    #[arg(long)]
    pub dir: Option<PathBuf>,
    /// Skip the confirmation.
    #[arg(long)]
    pub yes: bool,
}

pub fn run(ctx: &Context, prompt: &mut Prompt, args: SetupArgs) -> anyhow::Result<()> {
    const ALL_USERS_DIR: &str = "/opt/ajar-connectors";
    const ALL_USERS_LINK: &str = "/usr/local/bin/ajar-connectors";
    if let Ok(root) = ctx.root() {
        anyhow::bail!(
            "this ajar-connectors is already set up in {}; to set up another folder, run setup \
             from a downloaded binary or package",
            root.path().display()
        );
    }
    let as_root = ctx.as_root;
    let scope = if as_root {
        Scope::AllUsers
    } else {
        Scope::CurrentUser
    };

    let dir = match args.dir {
        Some(dir) => dir,
        None => {
            let home_dir =
                std::env::var_os("HOME").map(|home| Path::new(&home).join(".ajar-connectors"));
            let options = [
                match as_root {
                    true => MenuOption::available(
                        format!("{ALL_USERS_DIR}, for all users"),
                        Some(PathBuf::from(ALL_USERS_DIR)),
                    ),
                    false => MenuOption::unavailable(
                        format!("{ALL_USERS_DIR}, for all users"),
                        Some(PathBuf::from(ALL_USERS_DIR)),
                        "needs root: rerun with sudo",
                    ),
                },
                match (&home_dir, as_root) {
                    (Some(home_dir), false) => MenuOption::available(
                        format!("{}, for the current user", home_dir.display()),
                        Some(home_dir.clone()),
                    ),
                    (_, true) => MenuOption::unavailable(
                        "~/.ajar-connectors, for the current user",
                        None,
                        "not as root, since it would belong to root",
                    ),
                    (None, false) => MenuOption::unavailable(
                        "~/.ajar-connectors, for the current user",
                        None,
                        "HOME is not set",
                    ),
                },
                MenuOption::available("another folder", None),
            ];
            match prompt.choose("Where should ajar-connectors live?", "--dir", &options)? {
                Some(dir) => dir.clone(),
                None => {
                    let answer = prompt.ask("Folder", "--dir", None)?;
                    match (answer.strip_prefix("~/"), std::env::var_os("HOME")) {
                        (Some(rest), Some(home)) => Path::new(&home).join(rest),
                        _ => PathBuf::from(answer),
                    }
                }
            }
        }
    };
    let dir = std::path::absolute(&dir).with_context(|| format!("resolving {}", dir.display()))?;

    if dir.exists() {
        anyhow::bail!(
            "{} already exists: choose a folder that doesn't",
            dir.display()
        );
    }
    let link = Path::new(ALL_USERS_LINK);
    if scope == Scope::AllUsers && link.symlink_metadata().is_ok() {
        anyhow::bail!(
            "{ALL_USERS_LINK} already exists: remove it if it is an old ajar-connectors, then \
             run setup again"
        );
    }
    let packages = package_tarballs(&ctx.binary)?;

    let mut plan = Plan::default();
    plan.add_step(format!(
        "create {} with bin/, connectors/, packages/ and instances/",
        dir.display()
    ));
    plan.add_step(format!(
        "copy {} into {}/bin/",
        ctx.binary.display(),
        dir.display()
    ));
    if !packages.is_empty() {
        plan.add_step(format!(
            "copy {} packages into {}/packages/",
            packages.len(),
            dir.display()
        ));
    }
    match scope {
        Scope::AllUsers => plan.add_step(format!("link {ALL_USERS_LINK} to it, for all users")),
        Scope::CurrentUser => plan.add_step("print the line that puts it on your PATH"),
    }
    if !prompt.confirm(&plan, args.yes)? {
        prompt.say("Nothing was changed.")?;
        return Ok(());
    }

    let root = Root::create(&dir, scope)?;
    if let Err(e) = fill_root(ctx, &root, &packages) {
        // The checks above passed, so this is a disk or permission problem midway: leave no
        // half-made root behind.
        let _ = std::fs::remove_dir_all(&dir);
        return Err(e);
    }
    let binary = root.bin_dir().join("ajar-connectors");
    match scope {
        Scope::AllUsers => {
            std::os::unix::fs::symlink(&binary, link)
                .with_context(|| format!("linking {ALL_USERS_LINK}"))?;
            prompt.say(&format!(
                "Set up in {} for all users, who run ajar-connectors with sudo.",
                dir.display()
            ))?;
        }
        Scope::CurrentUser => {
            prompt.say(&format!("Set up in {}. To run ajar-connectors from anywhere, add this line to your shell's startup file:", dir.display()))?;
            prompt.say(&format!(
                "  export PATH=\"{}:$PATH\"",
                root.bin_dir().display()
            ))?;
        }
    }
    prompt
        .say("Next: ajar-connectors list --available, then ajar-connectors install <connector>.")?;
    Ok(())
}

/// Copies this binary and the package tar's packages into a new root.
fn fill_root(ctx: &Context, root: &Root, packages: &[PathBuf]) -> anyhow::Result<()> {
    let binary = root.bin_dir().join("ajar-connectors");
    std::fs::copy(&ctx.binary, &binary)
        .with_context(|| format!("copying {} to {}", ctx.binary.display(), binary.display()))?;
    std::fs::set_permissions(&binary, Permissions::from_mode(0o755))
        .with_context(|| format!("making {} executable", binary.display()))?;
    for tarball in packages {
        let name = tarball
            .file_name()
            .and_then(|name| name.to_str())
            .with_context(|| format!("{} has no file name", tarball.display()))?;
        for name in [name.to_owned(), format!("{name}.sha256")] {
            let (file, target) = (
                tarball.with_file_name(&name),
                root.packages_dir().join(&name),
            );
            std::fs::copy(&file, &target)
                .with_context(|| format!("copying {} to {}", file.display(), target.display()))?;
        }
    }
    Ok(())
}

/// The release tarballs in the `packages/` beside this binary's `bin/`, as a package tar lays
/// them out. Each must be a release tarball that matches its `.sha256`.
fn package_tarballs(binary: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let Some(bin_dir) = binary.parent().filter(|dir| dir.ends_with("bin")) else {
        return Ok(Vec::new());
    };
    let Some(packages_dir) = bin_dir.parent().map(|dir| dir.join("packages")) else {
        return Ok(Vec::new());
    };
    let entries = match std::fs::read_dir(&packages_dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", packages_dir.display())),
    };
    let mut tarballs = Vec::new();
    for entry in entries {
        let path = entry
            .with_context(|| format!("reading {}", packages_dir.display()))?
            .path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        if name.ends_with(".sha256") {
            continue;
        }
        if TarballName::parse(name).is_none() {
            anyhow::bail!(
                "{} is not a connector release tarball: remove it from the package",
                path.display()
            );
        }
        ajar_tooling::releases::check_sha256(&path)?;
        tarballs.push(path);
    }
    tarballs.sort();
    Ok(tarballs)
}
