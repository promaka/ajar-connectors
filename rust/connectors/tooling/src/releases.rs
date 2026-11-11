// SPDX-License-Identifier: Apache-2.0
//! Connector releases: the tarballs CI publishes on this repository's GitHub releases, named
//! `ajar-<connector-type>-<version>-<platform>.tar.gz`, each with a `.sha256` file beside it.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::Duration;

use regex::Regex;
use semver::Version;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::invite::ConnectorType;

const MAX_TARBALL_BYTES: u64 = 256 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Platform {
    X86_64Linux,
    Aarch64Linux,
}

impl Platform {
    /// The platform this tool runs on, or `None` when no connector is released for it.
    pub fn current() -> Option<Platform> {
        match (std::env::consts::OS, std::env::consts::ARCH) {
            ("linux", "x86_64") => Some(Platform::X86_64Linux),
            ("linux", "aarch64") => Some(Platform::Aarch64Linux),
            _ => None,
        }
    }

    pub fn parse(target_triple: &str) -> Option<Platform> {
        match target_triple {
            "x86_64-unknown-linux-gnu" => Some(Platform::X86_64Linux),
            "aarch64-unknown-linux-gnu" => Some(Platform::Aarch64Linux),
            _ => None,
        }
    }

    pub fn target_triple(self) -> &'static str {
        match self {
            Platform::X86_64Linux => "x86_64-unknown-linux-gnu",
            Platform::Aarch64Linux => "aarch64-unknown-linux-gnu",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TarballName {
    pub connector_type: ConnectorType,
    pub version: Version,
    pub platform: Platform,
}

impl TarballName {
    /// The name read from a tarball's file name, or `None` when it is not a connector tarball.
    pub fn parse(file_name: &str) -> Option<TarballName> {
        static NAME: LazyLock<Regex> = LazyLock::new(|| {
            Regex::new(
                r"^ajar-(?<connector_type>[a-z0-9-]+?)-(?<version>[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?)-(?<platform>[a-z0-9_]+-unknown-linux-gnu)\.tar\.gz$",
            )
            .expect("the regex parses fine")
        });
        let captures = NAME.captures(file_name)?;
        Some(TarballName {
            connector_type: ConnectorType::try_from(captures["connector_type"].to_owned()).ok()?,
            version: Version::parse(&captures["version"]).ok()?,
            platform: Platform::parse(&captures["platform"])?,
        })
    }

    /// False for the tools released from this repository under the same naming.
    pub fn is_connector_type(&self) -> bool {
        !["connectors", "doctor", "up"].contains(&self.connector_type.as_str())
    }
}

impl fmt::Display for TarballName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ajar-{}-{}-{}.tar.gz",
            self.connector_type,
            self.version,
            self.platform.target_triple()
        )
    }
}

/// A connector tarball published on GitHub for one platform.
#[derive(Debug, Clone)]
pub struct OnlineRelease {
    pub tarball: TarballName,
    url: String,
    /// `None` when the release has no `.sha256` for the tarball, which then can't be downloaded.
    sha256_url: Option<String>,
}

impl OnlineRelease {
    pub fn has_checksum(&self) -> bool {
        self.sha256_url.is_some()
    }
}

#[derive(Deserialize)]
struct GitHubRelease {
    tag_name: String,
    assets: Vec<GitHubAsset>,
}

#[derive(Deserialize)]
struct GitHubAsset {
    name: String,
    browser_download_url: String,
}

impl GitHubRelease {
    fn to_online_release(&self, platform: Platform) -> Option<OnlineRelease> {
        // Older releases don't have the layout this tool installs.
        const MIN_VERSION: Version = Version::new(0, 6, 6);

        let (asset, tarball) = self.assets.iter().find_map(|asset| {
            let tarball = TarballName::parse(&asset.name)?;
            (tarball.platform == platform).then_some((asset, tarball))
        })?;
        let release_tag = format!("{}-v{}", tarball.connector_type, tarball.version);
        if tarball.version < MIN_VERSION
            || !tarball.is_connector_type()
            || self.tag_name != release_tag
        {
            return None;
        }
        let sha256_name = format!("{}.sha256", asset.name);
        let sha256_url = self
            .assets
            .iter()
            .find(|a| a.name == sha256_name)
            .map(|a| a.browser_download_url.clone());
        Some(OnlineRelease {
            tarball,
            url: asset.browser_download_url.clone(),
            sha256_url,
        })
    }
}

/// Get every connector tarball released for `platform`. Other release assets are skipped.
pub fn list_online(platform: Platform) -> Result<Vec<OnlineRelease>, ReleaseError> {
    const RELEASES_URL: &str = "https://api.github.com/repos/promaka/ajar-connectors/releases";
    const PER_PAGE: usize = 100;
    let client = client()?;
    let mut online = Vec::new();
    for page in 1.. {
        let url = format!("{RELEASES_URL}?per_page={PER_PAGE}&page={page}");
        let response = client.get(&url).send()?;
        if response.status() == reqwest::StatusCode::FORBIDDEN
            || response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS
        {
            return Err(ReleaseError::RateLimited);
        }
        let releases: Vec<GitHubRelease> = response.error_for_status()?.json()?;
        online.extend(
            releases
                .iter()
                .filter_map(|r| r.to_online_release(platform)),
        );
        if releases.len() < PER_PAGE {
            break;
        }
    }
    online.sort_by(|a, b| a.tarball.cmp(&b.tarball));
    Ok(online)
}

/// Downloads `release` and its `.sha256` into `dir` and returns the tarball's path. Nothing is
/// written unless the tarball matches its checksum.
pub fn download(release: &OnlineRelease, dir: &Path) -> Result<PathBuf, ReleaseError> {
    let file_name = release.tarball.to_string();
    let sha256_url = release
        .sha256_url
        .as_deref()
        .ok_or_else(|| ReleaseError::NoChecksum(file_name.clone()))?;
    let client = client()?;
    let sha256_text = client.get(sha256_url).send()?.error_for_status()?.text()?;
    let mut tarball = Vec::new();
    client
        .get(&release.url)
        .send()?
        .error_for_status()?
        .take(MAX_TARBALL_BYTES + 1)
        .read_to_end(&mut tarball)
        .map_err(ReleaseError::io(format!("downloading {file_name}")))?;
    if tarball.len() as u64 > MAX_TARBALL_BYTES {
        return Err(ReleaseError::TooLarge(file_name));
    }
    check_digest(&tarball, &sha256_text, &file_name)?;

    let tarball_path = dir.join(&file_name);
    let sha256_path = dir.join(format!("{file_name}.sha256"));
    let mut written = Vec::new();
    for (path, bytes) in [
        (&tarball_path, tarball.as_slice()),
        (&sha256_path, sha256_text.as_bytes()),
    ] {
        let result = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .and_then(|mut f| f.write_all(bytes));
        if let Err(e) = result {
            // A file left behind would make every later download refuse to overwrite it.
            for path in written {
                let _ = std::fs::remove_file(path);
            }
            if e.kind() != std::io::ErrorKind::AlreadyExists {
                let _ = std::fs::remove_file(path);
            }
            return Err(ReleaseError::Io {
                what: format!("writing {}", path.display()),
                source: e,
            });
        }
        written.push(path);
    }
    Ok(tarball_path)
}

/// Checks the tarball at `path` against the `.sha256` file beside it.
pub fn check_sha256(path: &Path) -> Result<(), ReleaseError> {
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| ReleaseError::NotATarball(path.to_path_buf()))?;
    let sha256_path = path.with_file_name(format!("{file_name}.sha256"));
    let sha256_text = std::fs::read_to_string(&sha256_path).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            ReleaseError::NoChecksum(file_name.to_owned())
        } else {
            ReleaseError::Io {
                what: format!("reading {}", sha256_path.display()),
                source,
            }
        }
    })?;
    let mut tarball = Vec::new();
    File::open(path)
        .and_then(|f| f.take(MAX_TARBALL_BYTES + 1).read_to_end(&mut tarball))
        .map_err(ReleaseError::io(format!("reading {}", path.display())))?;
    if tarball.len() as u64 > MAX_TARBALL_BYTES {
        return Err(ReleaseError::TooLarge(file_name.to_owned()));
    }
    check_digest(&tarball, &sha256_text, file_name)
}

/// `sha256_text` is one `sha256sum` line: the digest in hex, two spaces, the file name.
fn check_digest(tarball: &[u8], sha256_text: &str, file_name: &str) -> Result<(), ReleaseError> {
    let Some((expected, listed_name)) = sha256_text.trim_end().split_once("  ") else {
        return Err(ReleaseError::BadChecksumFile(file_name.to_owned()));
    };
    if listed_name != file_name {
        return Err(ReleaseError::BadChecksumFile(file_name.to_owned()));
    }
    if hex::encode(Sha256::digest(tarball)) != expected {
        return Err(ReleaseError::ChecksumMismatch(file_name.to_owned()));
    }
    Ok(())
}

fn client() -> Result<reqwest::blocking::Client, ReleaseError> {
    // reqwest is built without a crypto provider, so the process needs aws-lc-rs installed.
    // An already installed provider is kept.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    Ok(reqwest::blocking::Client::builder()
        .user_agent(concat!("ajar-tooling/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(300))
        .build()?)
}

#[derive(Debug, thiserror::Error)]
pub enum ReleaseError {
    #[error("{what}")]
    Io {
        what: String,
        #[source]
        source: std::io::Error,
    },
    #[error("contacting GitHub")]
    Http(#[from] reqwest::Error),
    #[error(
        "GitHub refused the request, most likely its hourly limit for anonymous requests: \
         try again later, or install from a package"
    )]
    RateLimited,
    #[error("{} is not a connector tarball", .0.display())]
    NotATarball(PathBuf),
    #[error("{0} is larger than any connector tarball")]
    TooLarge(String),
    #[error("{0} has no .sha256 beside it, so it can't be checked")]
    NoChecksum(String),
    #[error("the .sha256 for {0} is not a sha256sum line for that file")]
    BadChecksumFile(String),
    #[error("{0} does not match its .sha256: the file is corrupt or was changed")]
    ChecksumMismatch(String),
}

impl ReleaseError {
    fn io(what: String) -> impl FnOnce(std::io::Error) -> ReleaseError {
        move |source| ReleaseError::Io { what, source }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADSB: &str = "ajar-adsb-0.6.7-x86_64-unknown-linux-gnu.tar.gz";

    #[test]
    fn tarball_name_round_trips_with_hyphens_in_type_and_version() {
        for name in [
            ADSB,
            "ajar-tak-cot-0.6.7-aarch64-unknown-linux-gnu.tar.gz",
            "ajar-generic-egress-1.0.0-rc.1-x86_64-unknown-linux-gnu.tar.gz",
        ] {
            let parsed = TarballName::parse(name).unwrap();
            assert_eq!(parsed.to_string(), name);
        }
        let parsed =
            TarballName::parse("ajar-tak-cot-0.6.7-aarch64-unknown-linux-gnu.tar.gz").unwrap();
        assert_eq!(parsed.connector_type.as_str(), "tak-cot");
        assert_eq!(parsed.version, Version::new(0, 6, 7));
        assert_eq!(parsed.platform, Platform::Aarch64Linux);
    }

    #[test]
    fn other_files_are_not_tarball_names() {
        for name in [
            "ajar-adsb-0.6.7-x86_64-unknown-linux-gnu.tar.gz.sha256",
            "ajar-adsb-0.6.7-riscv64-unknown-linux-gnu.tar.gz",
            "ajar-adsb-latest-x86_64-unknown-linux-gnu.tar.gz",
            "ajar-connector-0.6.7.tgz",
        ] {
            assert_eq!(TarballName::parse(name), None, "{name}");
        }
    }

    #[test]
    fn release_gives_its_tarball_for_this_platform_only_when_it_is_a_connector_type() {
        let release = |tag: &str, names: &[&str]| GitHubRelease {
            tag_name: tag.to_owned(),
            assets: names
                .iter()
                .map(|name| GitHubAsset {
                    name: (*name).to_owned(),
                    browser_download_url: format!("https://example.invalid/{name}"),
                })
                .collect(),
        };
        let online = |release: GitHubRelease| {
            release
                .to_online_release(Platform::X86_64Linux)
                .map(|r| (r.tarball.to_string(), r.has_checksum()))
        };

        let adsb = release(
            "adsb-v0.6.7",
            &[
                "ajar-adsb-0.6.7-aarch64-unknown-linux-gnu.tar.gz",
                ADSB,
                &format!("{ADSB}.sha256"),
            ],
        );
        assert_eq!(online(adsb), Some((ADSB.to_owned(), true)));

        let klv = "ajar-klv-0.6.7-x86_64-unknown-linux-gnu.tar.gz";
        assert_eq!(
            online(release("klv-v0.6.7", &[klv])),
            Some((klv.to_owned(), false))
        );

        for (tag, name) in [
            (
                "v0.6.5",
                "ajar-connectors-0.6.5-x86_64-unknown-linux-gnu.tar.gz",
            ),
            (
                "connectors-v0.7.0",
                "ajar-connectors-0.7.0-x86_64-unknown-linux-gnu.tar.gz",
            ),
            (
                "gmti-v0.6.5",
                "ajar-gmti-0.6.5-x86_64-unknown-linux-gnu.tar.gz",
            ),
            (
                "doctor-v0.6.7",
                "ajar-doctor-0.6.7-x86_64-unknown-linux-gnu.tar.gz",
            ),
            (
                "mavlink-v0.6.7",
                "ajar-mavlink-0.6.6-x86_64-unknown-linux-gnu.tar.gz",
            ),
            (
                "adsb-v0.6.7",
                "ajar-adsb-0.6.7-aarch64-unknown-linux-gnu.tar.gz",
            ),
        ] {
            assert_eq!(online(release(tag, &[name])), None, "{name}");
        }
    }

    #[test]
    fn local_tarball_is_checked_against_its_sha256() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(ADSB);
        std::fs::write(&path, b"tarball").unwrap();
        let digest = hex::encode(Sha256::digest(b"tarball"));
        let sha256_path = tmp.path().join(format!("{ADSB}.sha256"));

        std::fs::write(&sha256_path, format!("{digest}  {ADSB}\n")).unwrap();
        check_sha256(&path).unwrap();

        std::fs::write(&path, b"changed").unwrap();
        let err = check_sha256(&path).unwrap_err();
        assert!(matches!(err, ReleaseError::ChecksumMismatch(_)), "{err}");
    }

    #[test]
    fn sha256_for_another_file_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(ADSB);
        std::fs::write(&path, b"tarball").unwrap();
        let digest = hex::encode(Sha256::digest(b"tarball"));
        std::fs::write(
            tmp.path().join(format!("{ADSB}.sha256")),
            format!("{digest}  ajar-klv-0.6.7-x86_64-unknown-linux-gnu.tar.gz\n"),
        )
        .unwrap();
        let err = check_sha256(&path).unwrap_err();
        assert!(matches!(err, ReleaseError::BadChecksumFile(_)), "{err}");
    }

    #[test]
    fn tarball_without_sha256_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(ADSB);
        std::fs::write(&path, b"tarball").unwrap();
        let err = check_sha256(&path).unwrap_err();
        assert!(matches!(err, ReleaseError::NoChecksum(_)), "{err}");
    }
}
