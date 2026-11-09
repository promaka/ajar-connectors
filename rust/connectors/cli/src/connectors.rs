// SPDX-License-Identifier: Apache-2.0
//! Connector types and where each version can come from: installed in `connectors/`, a release
//! tarball in `packages/`, a binary file in the current folder, or an online release. Holds the
//! rules `install` follows to pick one, and installing into `connectors/<type>/<version>/`.

use std::fmt;
use std::fs::{File, OpenOptions, Permissions};
use std::io::ErrorKind;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use ajar_tooling::invite::ConnectorType;
use ajar_tooling::releases::{OnlineRelease, Platform, TarballName};
use anyhow::Context as _;
use flate2::read::GzDecoder;
use semver::Version;
use serde::{Deserialize, Serialize};
use tar::{Archive, EntryType};

use crate::context::Root;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum ConnectorVersion {
    /// Installed from a binary file, whose version the tool can't know.
    Local,
    Release(Version),
}

impl TryFrom<String> for ConnectorVersion {
    type Error = anyhow::Error;

    fn try_from(text: String) -> anyhow::Result<Self> {
        match text.as_str() {
            "local" => Ok(ConnectorVersion::Local),
            _ => Version::parse(&text)
                .map(ConnectorVersion::Release)
                .map_err(|_| {
                    anyhow::anyhow!("{text:?} is not a connector version: use local or 0.6.7")
                }),
        }
    }
}

impl From<ConnectorVersion> for String {
    fn from(version: ConnectorVersion) -> String {
        version.to_string()
    }
}

impl fmt::Display for ConnectorVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectorVersion::Local => f.write_str("local"),
            ConnectorVersion::Release(version) => version.fmt(f),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Location {
    /// The version folder in `connectors/`.
    Installed(PathBuf),
    /// A release tarball in `packages/`, with its `.sha256` beside it.
    Package(PathBuf),
    /// An executable `ajar-<type>` in the current folder.
    BinaryFile(PathBuf),
    Online(OnlineRelease),
}

#[derive(Debug, Clone)]
pub struct AvailableConnector {
    pub connector_type: ConnectorType,
    pub version: ConnectorVersion,
    pub location: Location,
}

#[derive(Debug)]
pub enum InstallSource {
    /// Nothing changes. `newer` is a newer version in `packages/`.
    AlreadyInstalled {
        installed: AvailableConnector,
        newer: Option<AvailableConnector>,
    },
    Install(AvailableConnector),
}

/// Every connector on this machine, and the online releases once asked for.
#[derive(Debug)]
pub struct Overview {
    platform: Option<Platform>,
    on_machine: Vec<AvailableConnector>,
    /// Files in `packages/` and the current folder, and online releases once asked for, that
    /// look like connectors but can't be installed, with the reason.
    pub unusable: Vec<(PathBuf, String)>,
    /// `None` until asked for. The error is the reason online releases are unavailable.
    online: Option<Result<Vec<AvailableConnector>, String>>,
}

impl Overview {
    pub fn on_machine(
        root: &Root,
        current_dir: &Path,
        platform: Option<Platform>,
    ) -> anyhow::Result<Overview> {
        let mut overview = Overview {
            platform,
            on_machine: Vec::new(),
            unusable: Vec::new(),
            online: None,
        };
        overview.add_installed(&root.connectors_dir())?;
        overview.add_packages(&root.packages_dir())?;
        overview.add_binary_files(current_dir)?;
        // Folder and file names sort 0.10.0 before 0.6.7, so each section is sorted again by
        // type and then by version.
        let section = |location: &Location| match location {
            Location::Installed(_) => 0,
            Location::Package(_) => 1,
            Location::BinaryFile(_) => 2,
            Location::Online(_) => 3,
        };
        overview.on_machine.sort_by(|a, b| {
            section(&a.location)
                .cmp(&section(&b.location))
                .then_with(|| a.connector_type.cmp(&b.connector_type))
                .then_with(|| a.version.cmp(&b.version))
        });
        Ok(overview)
    }

    pub fn on_machine_connectors(&self) -> &[AvailableConnector] {
        &self.on_machine
    }

    /// The online releases for this platform, listed from GitHub on first use. A release
    /// without a `.sha256` can't be checked, so it goes to `unusable`.
    pub fn online(&mut self) -> Result<&[AvailableConnector], &str> {
        let online = match self.online.take() {
            Some(online) => online,
            None => {
                let listed = match self.platform {
                    Some(platform) => {
                        ajar_tooling::releases::list_online(platform).map_err(|e| e.to_string())
                    }
                    None => Err(format!(
                        "no connectors are released for {} on {}",
                        std::env::consts::OS,
                        std::env::consts::ARCH
                    )),
                };
                match listed {
                    Ok(releases) => {
                        let (usable, unchecked): (Vec<_>, Vec<_>) =
                            releases.into_iter().partition(|r| r.has_checksum());
                        self.unusable.extend(unchecked.into_iter().map(|release| {
                            (
                                PathBuf::from(release.tarball.to_string()),
                                "released without a .sha256 to check it with".to_owned(),
                            )
                        }));
                        Ok(usable
                            .into_iter()
                            .map(|release| AvailableConnector {
                                connector_type: release.tarball.connector_type.clone(),
                                version: ConnectorVersion::Release(release.tarball.version.clone()),
                                location: Location::Online(release),
                            })
                            .collect())
                    }
                    Err(e) => Err(e),
                }
            }
        };
        self.online
            .insert(online)
            .as_deref()
            .map_err(String::as_str)
    }

    /// Picks where `install` takes `connector_type` from: installed wins and changes nothing,
    /// then a package or a binary file (refused when both are there), then online. With
    /// `version`, binary files are skipped because their version is unknown.
    pub fn find_for_install(
        &mut self,
        connector_type: &ConnectorType,
        version: Option<&Version>,
    ) -> anyhow::Result<InstallSource> {
        let wanted = |c: &&AvailableConnector| {
            &c.connector_type == connector_type
                && version.is_none_or(|v| c.version == ConnectorVersion::Release(v.clone()))
        };
        let spec = match version {
            Some(version) => format!("{connector_type}@{version}"),
            None => connector_type.to_string(),
        };

        let installed = self
            .on_machine
            .iter()
            .filter(wanted)
            .filter(|c| matches!(c.location, Location::Installed(_)))
            .max_by(|a, b| a.version.cmp(&b.version));
        if let Some(installed) = installed {
            let newer = self
                .on_machine
                .iter()
                .filter(|c| &c.connector_type == connector_type)
                .filter(|c| matches!(c.location, Location::Package(_)))
                .filter(|c| c.version > installed.version)
                .max_by(|a, b| a.version.cmp(&b.version));
            return Ok(InstallSource::AlreadyInstalled {
                installed: installed.clone(),
                newer: newer.cloned(),
            });
        }

        let package = self
            .on_machine
            .iter()
            .filter(wanted)
            .filter(|c| matches!(c.location, Location::Package(_)))
            .max_by(|a, b| a.version.cmp(&b.version));
        let binary_file = self
            .on_machine
            .iter()
            .filter(|c| version.is_none() && wanted(c))
            .find(|c| matches!(c.location, Location::BinaryFile(_)));
        match (package, binary_file) {
            (
                Some(AvailableConnector {
                    location: Location::Package(package),
                    ..
                }),
                Some(AvailableConnector {
                    location: Location::BinaryFile(binary_file),
                    ..
                }),
            ) => anyhow::bail!(
                "both {} and {} can install {spec}: remove one, or install the package with \
                 {spec}@<version>, since a named version skips binary files",
                package.display(),
                binary_file.display()
            ),
            (Some(found), None) | (None, Some(found)) => {
                return Ok(InstallSource::Install(found.clone()))
            }
            _ => {}
        }

        let binary_hint = match version {
            Some(_) => String::new(),
            None => format!(
                "; to install a binary you built, put it in the current folder as \
                 ajar-{connector_type}"
            ),
        };
        let online = match self.online() {
            Ok(online) => online,
            Err(reason) => anyhow::bail!(
                "{spec} is not installed, not in packages/ and not in the current folder, \
                 and online releases are unavailable: {reason}{binary_hint}"
            ),
        };
        let found = online
            .iter()
            .filter(wanted)
            .max_by(|a, b| a.version.cmp(&b.version))
            .with_context(|| {
                format!("{spec} is not on this machine and not released online{binary_hint}")
            })?;
        Ok(InstallSource::Install(found.clone()))
    }

    fn add_installed(&mut self, connectors_dir: &Path) -> anyhow::Result<()> {
        for type_dir in read_dir(connectors_dir)? {
            let Some(name) = file_name(&type_dir) else {
                continue;
            };
            let connector_type = ConnectorType::try_from(name.to_owned()).with_context(|| {
                format!("{} is not a connector type folder", type_dir.display())
            })?;
            for version_dir in read_dir(&type_dir)? {
                let Some(name) = file_name(&version_dir) else {
                    continue;
                };
                let version = ConnectorVersion::try_from(name.to_owned()).with_context(|| {
                    format!("{} is not a version folder", version_dir.display())
                })?;
                self.on_machine.push(AvailableConnector {
                    connector_type: connector_type.clone(),
                    version,
                    location: Location::Installed(version_dir),
                });
            }
        }
        Ok(())
    }

    fn add_packages(&mut self, packages_dir: &Path) -> anyhow::Result<()> {
        for path in read_dir(packages_dir)? {
            let Some(name) = file_name(&path) else {
                continue;
            };
            if name.ends_with(".sha256") {
                continue;
            }
            let Some(tarball) = TarballName::parse(name) else {
                self.unusable
                    .push((path, "not a connector release tarball".to_owned()));
                continue;
            };
            if !tarball.is_connector_type() {
                self.unusable
                    .push((path, "a tool, not a connector type".to_owned()));
                continue;
            }
            if Some(tarball.platform) != self.platform {
                let reason = format!(
                    "built for {}, not for this machine",
                    tarball.platform.target_triple()
                );
                self.unusable.push((path, reason));
                continue;
            }
            if !path.with_file_name(format!("{name}.sha256")).exists() {
                self.unusable
                    .push((path, "no .sha256 beside it to check it with".to_owned()));
                continue;
            }
            self.on_machine.push(AvailableConnector {
                connector_type: tarball.connector_type,
                version: ConnectorVersion::Release(tarball.version),
                location: Location::Package(path),
            });
        }
        Ok(())
    }

    fn add_binary_files(&mut self, current_dir: &Path) -> anyhow::Result<()> {
        for path in read_dir(current_dir)? {
            let Some(connector_type) = file_name(&path)
                .and_then(|name| name.strip_prefix("ajar-"))
                // The command itself and the tools it replaced.
                .filter(|name| !["connectors", "doctor", "up"].contains(name))
                .and_then(|name| ConnectorType::try_from(name.to_owned()).ok())
            else {
                continue;
            };
            let metadata =
                std::fs::metadata(&path).with_context(|| format!("reading {}", path.display()))?;
            if !metadata.is_file() {
                continue;
            }
            if metadata.permissions().mode() & 0o111 == 0 {
                self.unusable.push((path, "not executable".to_owned()));
                continue;
            }
            self.on_machine.push(AvailableConnector {
                connector_type,
                version: ConnectorVersion::Local,
                location: Location::BinaryFile(path),
            });
        }
        Ok(())
    }
}

/// Installs `connector` into `connectors/<type>/<version>/` and returns that folder. An online
/// release is downloaded into `packages/` first and kept there; nothing is left in
/// `connectors/` when a step fails.
pub fn install(root: &Root, connector: &AvailableConnector) -> anyhow::Result<PathBuf> {
    let type_dir = root
        .connectors_dir()
        .join(connector.connector_type.as_str());
    let version_dir = type_dir.join(connector.version.to_string());
    if version_dir.exists() {
        anyhow::bail!("{} is already installed", version_dir.display());
    }
    std::fs::create_dir_all(&type_dir)
        .with_context(|| format!("creating {}", type_dir.display()))?;
    // Hidden, so a failed or running install never shows as an installed version.
    let staging = tempfile::Builder::new()
        .prefix(".installing-")
        .tempdir_in(&type_dir)
        .with_context(|| format!("creating a folder in {}", type_dir.display()))?;

    match &connector.location {
        Location::Installed(dir) => anyhow::bail!("{} is already installed", dir.display()),
        Location::Package(tarball) => {
            ajar_tooling::releases::check_sha256(tarball)?;
            unpack(tarball, staging.path())?;
        }
        Location::Online(release) => {
            let tarball = ajar_tooling::releases::download(release, &root.packages_dir())?;
            unpack(&tarball, staging.path())?;
        }
        Location::BinaryFile(file) => {
            let target = staging.path().join(
                file.file_name()
                    .with_context(|| format!("{} has no file name", file.display()))?,
            );
            std::fs::copy(file, &target).with_context(|| format!("copying {}", file.display()))?;
            std::fs::set_permissions(&target, Permissions::from_mode(0o755))
                .with_context(|| format!("making {} executable", target.display()))?;
        }
    }
    installed_binary(staging.path())?;

    std::fs::set_permissions(staging.path(), Permissions::from_mode(0o755))
        .with_context(|| format!("opening up {}", staging.path().display()))?;
    std::fs::rename(staging.path(), &version_dir)
        .with_context(|| format!("moving the install into {}", version_dir.display()))?;
    // The folder has moved, so there is nothing left for the guard to remove.
    let _ = staging.keep();
    Ok(version_dir)
}

/// Removes an installed version folder, and its type folder when that is left empty.
pub fn uninstall(version_dir: &Path) -> anyhow::Result<()> {
    std::fs::remove_dir_all(version_dir)
        .with_context(|| format!("removing {}", version_dir.display()))?;
    if let Some(type_dir) = version_dir.parent() {
        if read_dir(type_dir)?.is_empty() {
            std::fs::remove_dir(type_dir)
                .with_context(|| format!("removing {}", type_dir.display()))?;
        }
    }
    Ok(())
}

/// The connector's binary in an installed version folder: its one executable file.
pub fn installed_binary(version_dir: &Path) -> anyhow::Result<PathBuf> {
    let mut executables = Vec::new();
    for path in read_dir(version_dir)? {
        let metadata = std::fs::symlink_metadata(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        if metadata.is_file() && metadata.permissions().mode() & 0o111 != 0 {
            executables.push(path);
        }
    }
    match <[PathBuf; 1]>::try_from(executables) {
        Ok([binary]) => Ok(binary),
        Err(found) => anyhow::bail!(
            "{} holds {} executable files, and a connector holds exactly one",
            version_dir.display(),
            found.len()
        ),
    }
}

/// Unpacks a release tarball's one top folder into `into`. Only files and folders inside that
/// folder are accepted.
fn unpack(tarball: &Path, into: &Path) -> anyhow::Result<()> {
    let top = file_name(tarball)
        .and_then(|name| name.strip_suffix(".tar.gz"))
        .with_context(|| format!("{} is not a .tar.gz", tarball.display()))?;
    let file = File::open(tarball).with_context(|| format!("opening {}", tarball.display()))?;
    let mut archive = Archive::new(GzDecoder::new(file));
    let unreadable = |e| anyhow::Error::new(e).context(format!("reading {}", tarball.display()));
    for entry in archive.entries().map_err(unreadable)? {
        let mut entry = entry.map_err(unreadable)?;
        let path = entry.path().map_err(unreadable)?.into_owned();
        let inside = path
            .strip_prefix(top)
            .ok()
            .filter(|inside| {
                inside
                    .components()
                    .all(|c| matches!(c, Component::Normal(_)))
            })
            .with_context(|| {
                format!(
                    "{} holds {}, which is outside its {top}/ folder",
                    tarball.display(),
                    path.display()
                )
            })?;
        let target = into.join(inside);
        match entry.header().entry_type() {
            EntryType::Directory => std::fs::create_dir_all(&target)
                .with_context(|| format!("creating {}", target.display()))?,
            EntryType::Regular => {
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent)
                        .with_context(|| format!("creating {}", parent.display()))?;
                }
                let mode = entry.header().mode().map_err(unreadable)? & 0o755;
                let mut out = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(mode)
                    .open(&target)
                    .with_context(|| format!("creating {}", target.display()))?;
                std::io::copy(&mut entry, &mut out)
                    .with_context(|| format!("unpacking {}", target.display()))?;
            }
            other => anyhow::bail!(
                "{} holds {} of type {other:?}, and a connector tarball holds only files and \
                 folders",
                tarball.display(),
                path.display()
            ),
        }
    }
    Ok(())
}

/// The entries of `dir`, except hidden ones. A missing folder has none.
fn read_dir(dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
    };
    let mut paths = Vec::new();
    for entry in entries {
        let path = entry
            .with_context(|| format!("reading {}", dir.display()))?
            .path();
        if !file_name(&path).is_some_and(|name| name.starts_with('.')) {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

/// The last part of `path`, or `None` when it is not UTF-8.
fn file_name(path: &Path) -> Option<&str> {
    path.file_name().and_then(|name| name.to_str())
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use sha2::{Digest, Sha256};

    use super::*;
    use crate::context::Scope;

    const PLATFORM: Platform = Platform::X86_64Linux;

    struct Machine {
        _tmp: tempfile::TempDir,
        root: Root,
        current_dir: PathBuf,
    }

    fn machine() -> Machine {
        let tmp = tempfile::tempdir().unwrap();
        let root = Root::create(&tmp.path().join("root"), Scope::CurrentUser).unwrap();
        let current_dir = tmp.path().join("here");
        std::fs::create_dir(&current_dir).unwrap();
        Machine {
            _tmp: tmp,
            root,
            current_dir,
        }
    }

    fn connector_type(name: &str) -> ConnectorType {
        ConnectorType::try_from(name.to_owned()).unwrap()
    }

    /// Writes a release tarball and its `.sha256` into `packages/`. `extra` is one more entry
    /// path inside the tarball.
    fn add_package(machine: &Machine, name: &str, version: &str, extra: Option<&str>) -> PathBuf {
        let top = format!("ajar-{name}-{version}-{}", PLATFORM.target_triple());
        let mut tar = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::fast(),
        ));
        let entries = [
            (format!("{top}/ajar-{name}"), 0o755),
            (format!("{top}/configs/{name}.example.toml"), 0o644),
        ];
        let extra = extra.map(|path| (path.to_owned(), 0o644));
        for (path, mode) in entries.into_iter().chain(extra) {
            let mut header = tar::Header::new_gnu();
            header.set_size(4);
            header.set_mode(mode);
            header.set_entry_type(EntryType::Regular);
            // set_path refuses `..`, which a hostile tarball can still hold.
            header.as_gnu_mut().unwrap().name[..path.len()].copy_from_slice(path.as_bytes());
            header.set_cksum();
            tar.append(&header, &b"data"[..]).unwrap();
        }
        let bytes = tar.into_inner().unwrap().finish().unwrap();
        let file_name = format!("{top}.tar.gz");
        let path = machine.root.packages_dir().join(&file_name);
        std::fs::write(&path, &bytes).unwrap();
        let digest = hex::encode(Sha256::digest(&bytes));
        std::fs::write(
            path.with_file_name(format!("{file_name}.sha256")),
            format!("{digest}  {file_name}\n"),
        )
        .unwrap();
        path
    }

    fn add_binary_file(machine: &Machine, name: &str) -> PathBuf {
        let path = machine.current_dir.join(format!("ajar-{name}"));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o755)
            .open(&path)
            .unwrap();
        file.write_all(b"binary").unwrap();
        path
    }

    fn overview(machine: &Machine) -> Overview {
        let mut overview =
            Overview::on_machine(&machine.root, &machine.current_dir, Some(PLATFORM)).unwrap();
        overview.online = Some(Err("offline in tests".to_owned()));
        overview
    }

    fn release(version: &str) -> ConnectorVersion {
        ConnectorVersion::Release(Version::parse(version).unwrap())
    }

    #[test]
    fn installed_wins_and_names_a_newer_package() {
        let machine = machine();
        let package = add_package(&machine, "adsb", "0.6.6", None);
        let mut found = overview(&machine);
        let InstallSource::Install(older) = found
            .find_for_install(&connector_type("adsb"), None)
            .unwrap()
        else {
            panic!("expected the package");
        };
        install(&machine.root, &older).unwrap();
        std::fs::remove_file(&package).unwrap();
        add_package(&machine, "adsb", "0.6.7", None);

        let source = overview(&machine)
            .find_for_install(&connector_type("adsb"), None)
            .unwrap();
        let InstallSource::AlreadyInstalled { installed, newer } = source else {
            panic!("expected the installed version");
        };
        assert_eq!(installed.version, release("0.6.6"));
        assert_eq!(newer.unwrap().version, release("0.6.7"));
    }

    #[test]
    fn package_and_binary_file_together_are_refused() {
        let machine = machine();
        add_package(&machine, "adsb", "0.6.7", None);
        add_binary_file(&machine, "adsb");
        let err = overview(&machine)
            .find_for_install(&connector_type("adsb"), None)
            .unwrap_err();
        assert!(err.to_string().contains("remove one"), "{err}");
    }

    #[test]
    fn named_version_skips_binary_files_and_picks_that_package() {
        let machine = machine();
        add_package(&machine, "adsb", "0.6.6", None);
        add_package(&machine, "adsb", "0.6.7", None);
        add_binary_file(&machine, "adsb");
        let wanted = Version::parse("0.6.6").unwrap();
        let source = overview(&machine)
            .find_for_install(&connector_type("adsb"), Some(&wanted))
            .unwrap();
        let InstallSource::Install(found) = source else {
            panic!("expected a package");
        };
        assert_eq!(found.version, release("0.6.6"));
        assert!(matches!(found.location, Location::Package(_)));
    }

    #[test]
    fn nothing_found_offline_gives_the_reason() {
        let machine = machine();
        let err = overview(&machine)
            .find_for_install(&connector_type("adsb"), None)
            .unwrap_err();
        assert!(err.to_string().contains("offline in tests"), "{err}");
        assert!(err.to_string().contains("as ajar-adsb"), "{err}");
    }

    #[test]
    fn package_installs_into_its_version_folder() {
        let machine = machine();
        add_package(&machine, "adsb", "0.6.7", None);
        let InstallSource::Install(found) = overview(&machine)
            .find_for_install(&connector_type("adsb"), None)
            .unwrap()
        else {
            panic!("expected the package");
        };
        let dir = install(&machine.root, &found).unwrap();
        assert_eq!(dir, machine.root.connectors_dir().join("adsb/0.6.7"));
        assert_eq!(installed_binary(&dir).unwrap(), dir.join("ajar-adsb"));
        assert!(dir.join("configs/adsb.example.toml").is_file());
    }

    #[test]
    fn tarball_reaching_outside_its_folder_installs_nothing() {
        let machine = machine();
        add_package(&machine, "adsb", "0.6.7", Some("../escaped"));
        let InstallSource::Install(found) = overview(&machine)
            .find_for_install(&connector_type("adsb"), None)
            .unwrap()
        else {
            panic!("expected the package");
        };
        let err = install(&machine.root, &found).unwrap_err();
        assert!(format!("{err:#}").contains("outside its"), "{err:#}");
        let type_dir = machine.root.connectors_dir().join("adsb");
        assert_eq!(std::fs::read_dir(type_dir).unwrap().count(), 0);
    }

    #[test]
    fn versions_sort_as_versions_not_as_text() {
        let machine = machine();
        for version in ["0.10.0", "0.6.7", "0.9.0"] {
            add_package(&machine, "adsb", version, None);
        }
        let versions: Vec<String> = overview(&machine)
            .on_machine_connectors()
            .iter()
            .map(|c| c.version.to_string())
            .collect();
        assert_eq!(versions, ["0.6.7", "0.9.0", "0.10.0"]);
    }

    #[test]
    fn binary_file_installs_as_local() {
        let machine = machine();
        add_binary_file(&machine, "adsb");
        let InstallSource::Install(found) = overview(&machine)
            .find_for_install(&connector_type("adsb"), None)
            .unwrap()
        else {
            panic!("expected the binary file");
        };
        let dir = install(&machine.root, &found).unwrap();
        assert_eq!(dir, machine.root.connectors_dir().join("adsb/local"));
    }

    #[test]
    fn unusable_packages_are_listed_with_the_reason() {
        let machine = machine();
        let package = add_package(&machine, "adsb", "0.6.7", None);
        std::fs::remove_file(package.with_file_name(format!(
            "{}.sha256",
            package.file_name().unwrap().to_str().unwrap()
        )))
        .unwrap();
        std::fs::write(machine.root.packages_dir().join("notes.txt"), b"").unwrap();
        let overview = overview(&machine);
        let reasons: Vec<&str> = overview
            .unusable
            .iter()
            .map(|(_, reason)| reason.as_str())
            .collect();
        assert_eq!(
            reasons,
            [
                "no .sha256 beside it to check it with",
                "not a connector release tarball"
            ]
        );
    }
}
