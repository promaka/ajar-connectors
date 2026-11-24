// SPDX-License-Identifier: Apache-2.0
//! The context a command runs in: the root folder the running binary is installed in, with its
//! config, and the folder the command was started from. Built once, before any command.

use std::fs::{DirBuilder, OpenOptions};
use std::io::ErrorKind;
use std::io::Write;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use ajar_tooling::invite::ConnectorId;
use anyhow::Context as _;
use serde::{Deserialize, Serialize};

const CONFIG_FILE: &str = "ajar-connectors.toml";
const CONFIG_FORMAT: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Scope {
    /// Linked from `/usr/local/bin`, for every user on the machine.
    AllUsers,
    /// On the PATH of the user who set it up.
    CurrentUser,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub format: u32,
    pub scope: Scope,
}

/// A root folder: `bin/`, `connectors/`, `packages/`, `instances/` and `ajar-connectors.toml`.
#[derive(Debug)]
pub struct Root {
    path: PathBuf,
    pub config: Config,
}

impl Root {
    /// Creates the root at `path`, which must not exist yet, with its folders and config.
    pub fn create(path: &Path, scope: Scope) -> anyhow::Result<Root> {
        let root = Root {
            path: path.to_path_buf(),
            config: Config {
                format: CONFIG_FORMAT,
                scope,
            },
        };
        DirBuilder::new()
            .mode(0o755)
            .create(path)
            .with_context(|| format!("creating {}", path.display()))?;
        for (dir, mode) in [
            (root.bin_dir(), 0o755),
            (root.connectors_dir(), 0o755),
            (root.packages_dir(), 0o755),
            // Instance folders hold private keys.
            (root.instances_dir(), 0o700),
        ] {
            DirBuilder::new()
                .mode(mode)
                .create(&dir)
                .with_context(|| format!("creating {}", dir.display()))?;
        }
        let config_path = path.join(CONFIG_FILE);
        let config_toml = toml::to_string(&root.config)?;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&config_path)
            .and_then(|mut f| f.write_all(config_toml.as_bytes()))
            .with_context(|| format!("writing {}", config_path.display()))?;
        Ok(root)
    }

    /// The root at `path`, or `None` when it has no `ajar-connectors.toml`.
    fn open(path: &Path) -> anyhow::Result<Option<Root>> {
        let config_path = path.join(CONFIG_FILE);
        let text = match std::fs::read_to_string(&config_path) {
            Ok(text) => text,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).with_context(|| format!("reading {}", config_path.display())),
        };
        let config: Config = toml::from_str(&text)
            .with_context(|| format!("{} is not valid", config_path.display()))?;
        if config.format != CONFIG_FORMAT {
            anyhow::bail!(
                "{} is format {} and this tool reads format {CONFIG_FORMAT}: use the \
                 ajar-connectors that set it up",
                config_path.display(),
                config.format
            );
        }
        Ok(Some(Root {
            path: path.to_path_buf(),
            config,
        }))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn bin_dir(&self) -> PathBuf {
        self.path.join("bin")
    }

    /// Installed connector types, as `<connector-type>/<version>/`.
    pub fn connectors_dir(&self) -> PathBuf {
        self.path.join("connectors")
    }

    /// Release tarballs with their `.sha256`, to install from without a network.
    pub fn packages_dir(&self) -> PathBuf {
        self.path.join("packages")
    }

    pub fn instances_dir(&self) -> PathBuf {
        self.path.join("instances")
    }

    pub fn instance_dir(&self, connector_id: &ConnectorId) -> PathBuf {
        self.instances_dir().join(connector_id.as_str())
    }

    /// The private keys of requests whose invites haven't been joined yet, per connector ID.
    pub fn requests_dir(&self) -> PathBuf {
        self.instances_dir().join(".requests")
    }
}

#[derive(Debug)]
pub struct Context {
    /// `None` when the running binary is not in a root's `bin/`, as when run from a download.
    root: Option<Root>,
    pub current_dir: PathBuf,
    /// The running binary, with links followed.
    pub binary: PathBuf,
    /// Run by root, as with sudo.
    pub as_root: bool,
}

impl Context {
    pub fn load() -> anyhow::Result<Context> {
        let binary = std::env::current_exe()
            .and_then(|path| path.canonicalize())
            .context("finding the running ajar-connectors binary")?;
        let id = Command::new("id")
            .arg("-u")
            .output()
            .context("running id -u")?;
        Ok(Context {
            root: root_of(&binary)?,
            current_dir: std::env::current_dir().context("reading the current folder")?,
            binary,
            as_root: String::from_utf8_lossy(&id.stdout).trim() == "0",
        })
    }

    /// The root this binary is installed in. Every command but `setup` needs one. A root for
    /// all users belongs to root, so it is refused to anyone else up front.
    pub fn root(&self) -> anyhow::Result<&Root> {
        let root = self.root.as_ref().with_context(|| {
            format!(
                "{} is not set up: run it with `setup` first",
                self.binary.display()
            )
        })?;
        if root.config.scope == Scope::AllUsers && !self.as_root {
            anyhow::bail!(
                "{} is set up for all users and belongs to root: run ajar-connectors with sudo",
                root.path().display()
            );
        }
        Ok(root)
    }
}

/// A context for running a command in a test, as a user who is not root.
#[cfg(test)]
impl Context {
    pub fn in_root(root: Root, current_dir: PathBuf) -> Context {
        Context {
            root: Some(root),
            current_dir,
            binary: PathBuf::from("ajar-connectors"),
            as_root: false,
        }
    }
}

/// The root whose `bin/` holds `binary`, or `None` when there is none.
fn root_of(binary: &Path) -> anyhow::Result<Option<Root>> {
    let Some(bin_dir) = binary.parent() else {
        return Ok(None);
    };
    match (bin_dir.file_name(), bin_dir.parent()) {
        (Some(name), Some(root)) if name == "bin" => Root::open(root),
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_in_a_created_root_finds_it_through_a_link() {
        let tmp = tempfile::tempdir().unwrap();
        let tmp = tmp.path().canonicalize().unwrap();
        let root = Root::create(&tmp.join("ajar-connectors"), Scope::CurrentUser).unwrap();
        let binary = root.bin_dir().join("ajar-connectors");
        std::fs::write(&binary, b"").unwrap();
        let link = tmp.join("ajar-connectors-link");
        std::os::unix::fs::symlink(&binary, &link).unwrap();

        let found = root_of(&link.canonicalize().unwrap()).unwrap().unwrap();
        assert_eq!(found.path(), root.path());
        assert_eq!(found.config, root.config);
    }

    #[test]
    fn binary_outside_a_root_has_none() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        assert!(root_of(&bin.join("ajar-connectors")).unwrap().is_none());
        assert!(root_of(&tmp.path().join("ajar-connectors"))
            .unwrap()
            .is_none());
    }

    #[test]
    fn settings_with_an_unknown_field_are_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let root = Root::create(&tmp.path().join("root"), Scope::AllUsers).unwrap();
        let config_path = root.path().join(CONFIG_FILE);
        let mut text = std::fs::read_to_string(&config_path).unwrap();
        text.push_str("colour = \"blue\"\n");
        std::fs::write(&config_path, text).unwrap();
        let err = Root::open(root.path()).unwrap_err();
        assert!(format!("{err:#}").contains("unknown field"), "{err:#}");
    }

    #[test]
    fn existing_folder_is_not_made_a_root() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(Root::create(tmp.path(), Scope::AllUsers).is_err());
    }
}
