// SPDX-License-Identifier: Apache-2.0
//! The operator's vendor packet: a tar of `manifest.json`, `manifest.sig`,
//! and the files the manifest references.
//!
//! Trust model, in one paragraph: the packet travels over the operator
//! channel, like `ca.crt` always has. `manifest.sig` is an Ed25519 signature
//! under the deployment's EGRESS key over a domain-prefixed copy of the
//! manifest bytes, verified with the `egress.pub` in the packet; every public
//! file is then pinned by a sha256 in the manifest. Private keys ride in the
//! tar (mint flow only) but are never listed in `files[]`, so a verified
//! manifest reveals nothing secret. Tampering with anything after the
//! handover is detectable; the first handover's integrity rests on the
//! operator channel itself, exactly as it does for the CA today.
//!
//! Tar members MUST be plain filenames: no leading `./`, no directory
//! entries, no paths. This is contract, not implementation detail - the
//! first cross-repo smoke caught a real emitter tarring with `-C dir .`
//! (producing `./manifest.json` members) that this rule refused, exactly as
//! it would have refused a path-traversal entry. Emitters append by explicit
//! filename; this unpacker stays strict.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;
use sha2::Digest as _;

/// The domain prefix the signature covers, before the raw manifest bytes.
const SIG_DOMAIN: &[u8] = b"ajar-onboard-manifest:1\n";
/// The manifest major this build understands.
const SUPPORTED_MAJOR: u32 = 1;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub manifest_version: String,
    /// Absent means producer (the original flow).
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

/// A verified, unpacked packet: the manifest plus where its files landed.
pub struct Packet {
    pub manifest: Manifest,
    pub dir: PathBuf,
}

impl Packet {
    pub fn role(&self) -> &str {
        self.manifest.role.as_deref().unwrap_or("producer")
    }

    /// Absolute path of a file the manifest references.
    pub fn path(&self, rel: &str) -> PathBuf {
        self.dir.join(rel)
    }
}

/// Unpack `tar_path` into `dir`, verify the manifest signature and every
/// pinned checksum, and lock down any private key files.
pub fn open(tar_path: &Path, dir: &Path) -> anyhow::Result<Packet> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("creating working directory {}", dir.display()))?;
    let file = std::fs::File::open(tar_path)
        .with_context(|| format!("opening packet {}", tar_path.display()))?;
    let mut archive = tar::Archive::new(file);
    for entry in archive.entries().context("reading the packet tar")? {
        let mut entry = entry.context("reading a packet entry")?;
        let name = entry.path().context("packet entry path")?.into_owned();
        // Flat names only: a packet has no business writing outside its dir.
        if name.components().count() != 1
            || name
                .components()
                .any(|c| !matches!(c, std::path::Component::Normal(_)))
        {
            bail!(
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

    // Signature first: nothing else in the packet is trusted before this.
    let key_bytes: [u8; 32] = hex::decode(pub_hex.trim())
        .context("egress.pub is not hex")?
        .try_into()
        .map_err(|_| anyhow!("egress.pub must be a 32-byte Ed25519 key in hex"))?;
    let key = VerifyingKey::from_bytes(&key_bytes).context("egress.pub is not a valid key")?;
    let sig_bytes: [u8; 64] = hex::decode(sig_hex.trim())
        .context("manifest.sig is not hex")?
        .try_into()
        .map_err(|_| anyhow!("manifest.sig must be a 64-byte Ed25519 signature in hex"))?;
    let mut message = SIG_DOMAIN.to_vec();
    message.extend_from_slice(&manifest_bytes);
    key.verify(&message, &Signature::from_bytes(&sig_bytes))
        .map_err(|_| {
            anyhow!(
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
        bail!(
            "manifest_version {} is a different major than this ajar-up understands ({}); \
             update ajar-up (or the operator's tooling) so both speak the same packet",
            manifest.manifest_version,
            SUPPORTED_MAJOR
        );
    }

    // Every public file the manifest pins must be present and byte-identical.
    for f in &manifest.files {
        let data = std::fs::read(dir.join(&f.path))
            .with_context(|| format!("the manifest lists {} but the packet lacks it", f.path))?;
        let got = hex::encode(sha2::Sha256::digest(&data));
        if got != f.sha256.to_lowercase() {
            bail!(
                "{} does not match its manifest checksum (expected {}, got {got}); \
                 the packet is corrupt or altered - get a fresh one",
                f.path,
                f.sha256
            );
        }
    }

    // Private key material, if the tar carried any, is nobody else's to read.
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
