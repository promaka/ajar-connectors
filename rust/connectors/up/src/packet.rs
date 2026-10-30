// SPDX-License-Identifier: Apache-2.0
//! The operator's vendor packet: a tar of `manifest.json`, `manifest.sig`,
//! `egress.pub` and the files the manifest pins by sha256. The packet's own
//! `egress.pub` verifies the Ed25519 signature over a domain-prefixed manifest,
//! so its origin rests on the operator channel. Private keys ride in the tar
//! (mint flow only), never in `files[]`. Members are plain filenames, no `./`.

use std::path::{Path, PathBuf};

use anyhow::Context;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;
use sha2::Digest as _;

/// Prefixed to the raw manifest bytes before signing.
const SIG_DOMAIN: &[u8] = b"ajar-onboard-manifest:1\n";
const SUPPORTED_MAJOR: u32 = 1;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub manifest_version: String,
    /// `producer` or `consumer`; absent is producer. See [`Packet::role`].
    #[serde(default)]
    pub role: Option<String>,
    pub source_id: String,
    pub nats_url: String,
    // Producer fields.
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub transport: Option<serde_json::Value>,
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub spool: Option<serde_json::Value>,
    #[serde(default)]
    pub entity_types: Option<Vec<String>>,
    #[serde(default)]
    pub ontology_version: Option<String>,
    // Consumer fields.
    #[serde(default)]
    pub egress_subject: Option<String>,
    #[serde(default)]
    pub formats: Option<Vec<String>>,
    #[serde(default)]
    pub egress_verifying_key_hex: Option<String>,
    pub keys: Keys,
    pub files: Vec<FileEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Keys {
    #[serde(default)]
    pub signing_key_path: Option<String>,
    #[serde(default)]
    pub mtls_cert_path: Option<String>,
    #[serde(default)]
    pub mtls_key_path: Option<String>,
    #[serde(default)]
    pub ca_cert_path: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileEntry {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Producer,
    Consumer,
}

/// A verified, unpacked packet and the directory its files landed in.
pub struct Packet {
    pub manifest: Manifest,
    pub dir: PathBuf,
}

impl Packet {
    pub fn role(&self) -> anyhow::Result<Role> {
        match self.manifest.role.as_deref() {
            None | Some("producer") => Ok(Role::Producer),
            Some("consumer") => Ok(Role::Consumer),
            Some(other) => anyhow::bail!(
                "this packet's role is {other:?}, which this ajar-up does not know; \
                 update ajar-up"
            ),
        }
    }

    /// A file the manifest references, joined onto the unpack directory.
    pub fn path(&self, rel: &str) -> PathBuf {
        self.dir.join(rel)
    }
}

/// Unpack `tar_path` into `dir`, verify the manifest signature and every
/// pinned checksum, and make any private key files mode 600.
pub fn open(tar_path: &Path, dir: &Path) -> anyhow::Result<Packet> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("creating working directory {}", dir.display()))?;
    let file = std::fs::File::open(tar_path).with_context(|| {
        format!(
            "opening packet {} (the <id>.packet.tar file your operator sent)",
            tar_path.display()
        )
    })?;
    let not_a_packet = || {
        format!(
            "{} is not a packet: expected the tar archive your operator produced with \
             `ajar onboard`",
            tar_path.display()
        )
    };
    let mut archive = tar::Archive::new(file);
    for entry in archive.entries().with_context(not_a_packet)? {
        let mut entry = entry.with_context(not_a_packet)?;
        let name = entry.path().context("packet entry path")?.into_owned();
        if name.components().count() != 1
            || name
                .components()
                .any(|c| !matches!(c, std::path::Component::Normal(_)))
        {
            anyhow::bail!(
                "packet entry {:?} is not a plain filename; refusing to unpack it",
                name
            );
        }
        entry
            .unpack(dir.join(&name))
            .with_context(|| format!("unpacking {:?}", name))?;
    }

    let manifest_bytes =
        std::fs::read(dir.join("manifest.json")).context("the packet has no manifest.json")?;
    let sig_hex = std::fs::read_to_string(dir.join("manifest.sig"))
        .context("the packet has no manifest.sig")?;
    let pub_hex =
        std::fs::read_to_string(dir.join("egress.pub")).context("the packet has no egress.pub")?;

    // The manifest is parsed only after its signature verifies.
    let key_bytes: [u8; 32] = hex::decode(pub_hex.trim())
        .context("egress.pub is not hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("egress.pub must be a 32-byte Ed25519 key in hex"))?;
    let key = VerifyingKey::from_bytes(&key_bytes).context("egress.pub is not a valid key")?;
    let sig_bytes: [u8; 64] = hex::decode(sig_hex.trim())
        .context("manifest.sig is not hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("manifest.sig must be a 64-byte Ed25519 signature in hex"))?;
    let mut message = SIG_DOMAIN.to_vec();
    message.extend_from_slice(&manifest_bytes);
    key.verify(&message, &Signature::from_bytes(&sig_bytes))
        .map_err(|_| {
            anyhow::anyhow!(
                "the manifest signature does not verify under the packet's egress key. \
                 The packet was altered after your operator issued it, or was issued \
                 by a different deployment. Get a fresh packet over the operator \
                 channel; do not use this one."
            )
        })?;

    let manifest: Manifest =
        serde_json::from_slice(&manifest_bytes).context("parsing manifest.json")?;
    let major: u32 = manifest
        .manifest_version
        .split('.')
        .next()
        .unwrap_or("")
        .parse()
        .with_context(|| format!("manifest_version {:?}", manifest.manifest_version))?;
    if major != SUPPORTED_MAJOR {
        anyhow::bail!(
            "manifest_version {} is a different major than this ajar-up understands ({}); \
             update ajar-up (or the operator's tooling) so both speak the same packet",
            manifest.manifest_version,
            SUPPORTED_MAJOR
        );
    }

    for f in &manifest.files {
        let data = std::fs::read(dir.join(&f.path))
            .with_context(|| format!("the manifest lists {} but the packet lacks it", f.path))?;
        let got = hex::encode(sha2::Sha256::digest(&data));
        if !got.eq_ignore_ascii_case(&f.sha256) {
            anyhow::bail!(
                "{} does not match its manifest checksum (expected {}, got {got}); \
                 the packet is corrupt or altered - get a fresh one",
                f.path,
                f.sha256
            );
        }
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for name in [
            manifest.keys.signing_key_path.as_deref(),
            manifest.keys.mtls_key_path.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            let p = dir.join(name);
            if p.exists() {
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))
                    .with_context(|| format!("locking down {}", p.display()))?;
            }
        }
    }

    Ok(Packet {
        manifest,
        dir: dir.to_path_buf(),
    })
}
