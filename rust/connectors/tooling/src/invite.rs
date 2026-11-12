// SPDX-License-Identifier: Apache-2.0
//! The invite: what `ajar invite` writes and `ajar-connectors join` reads. A tar of
//! `manifest.json`, `manifest.sig` and the files the manifest lists by sha256. The signature
//! is checked against the `egress.pub` inside the same tar, so a good one shows only that the
//! invite is intact.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The manifest format this crate reads and writes. Any other is refused.
pub const FORMAT: u32 = 2;

const SIGNATURE_DOMAIN: &[u8] = b"ajar-invite-manifest:2\n";
const MANIFEST: &str = "manifest.json";
const MANIFEST_SIG: &str = "manifest.sig";

/// A connector's identity on the bus. It becomes a NATS subject token, a registry key, a
/// certificate CN and the instance folder name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ConnectorId(String);

impl ConnectorId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ConnectorId {
    type Error = InviteError;

    fn try_from(id: String) -> Result<Self, InviteError> {
        // These carry fleet-wide bus permissions.
        const RESERVED: [&str; 4] = [
            "ajar-core",
            "ajar-core-sys",
            "ajar-connector",
            "ajar-consumer",
        ];
        if !is_valid_name(&id) {
            return Err(InviteError::ConnectorId {
                id,
                reason: "use lowercase letters, digits and hyphens, with no hyphen at either end",
            });
        }
        if RESERVED.contains(&id.as_str()) {
            return Err(InviteError::ConnectorId {
                id,
                reason: "name is reserved for Ajar's own services",
            });
        }
        Ok(ConnectorId(id))
    }
}

impl From<ConnectorId> for String {
    fn from(id: ConnectorId) -> String {
        id.0
    }
}

impl fmt::Display for ConnectorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The connector software, as its releases name it: `adsb`, `tak-egress`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ConnectorType(String);

impl ConnectorType {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ConnectorType {
    type Error = InviteError;

    fn try_from(name: String) -> Result<Self, InviteError> {
        if !is_valid_name(&name) {
            return Err(InviteError::ConnectorType(name));
        }
        Ok(ConnectorType(name))
    }
}

impl From<ConnectorType> for String {
    fn from(name: ConnectorType) -> String {
        name.0
    }
}

impl fmt::Display for ConnectorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn is_valid_name(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('-')
        && !s.ends_with('-')
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// A producer publishes events, a consumer reads Core's egress.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "snake_case")]
pub enum Invite {
    Producer(ProducerInvite),
    Consumer(ConsumerInvite),
}

impl Invite {
    pub fn connector_id(&self) -> &ConnectorId {
        match self {
            Invite::Producer(p) => &p.connector_id,
            Invite::Consumer(c) => &c.connector_id,
        }
    }

    pub fn connector_type(&self) -> &ConnectorType {
        match self {
            Invite::Producer(p) => &p.connector_type,
            Invite::Consumer(c) => &c.connector_type,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProducerInvite {
    pub connector_id: ConnectorId,
    pub connector_type: ConnectorType,
    pub nats_url: String,
    pub subject: String,
    pub entity_types: Vec<String>,
    /// Set when the invite added types to the ontology.
    pub ontology_version: Option<String>,
    /// The connector's `[transport]` table, checked by the connector itself.
    pub transport: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumerInvite {
    pub connector_id: ConnectorId,
    pub connector_type: ConnectorType,
    pub nats_url: String,
    pub egress_subject: String,
}

/// Files an invite can hold besides its manifest
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InviteFile {
    CaCert,
    EgressPublicKey,
    MtlsCert,
    MtlsKey,
    EventSigningKey,
}

impl InviteFile {
    const ALL: [InviteFile; 5] = [
        InviteFile::CaCert,
        InviteFile::EgressPublicKey,
        InviteFile::MtlsCert,
        InviteFile::MtlsKey,
        InviteFile::EventSigningKey,
    ];

    /// The file's name inside the invite tar and in the unpacked folder.
    pub fn member_name(self) -> &'static str {
        match self {
            InviteFile::CaCert => "ca.crt",
            InviteFile::EgressPublicKey => "egress.pub",
            InviteFile::MtlsCert => "mtls.crt",
            InviteFile::MtlsKey => "mtls.key",
            InviteFile::EventSigningKey => "signing.key",
        }
    }

    /// A private key: unpacked with mode 600, and it makes the invite itself a secret.
    pub fn is_secret(self) -> bool {
        matches!(self, InviteFile::MtlsKey | InviteFile::EventSigningKey)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: u32,
    invite: Invite,
    /// The sha256 of each file in hex, by member name.
    files: BTreeMap<String, String>,
}

fn check_file_set(invite: &Invite, files: &BTreeSet<InviteFile>) -> Result<(), InviteError> {
    for needed in [
        InviteFile::CaCert,
        InviteFile::EgressPublicKey,
        InviteFile::MtlsCert,
    ] {
        if !files.contains(&needed) {
            return Err(InviteError::MissingMember(needed.member_name()));
        }
    }
    // The private keys travel together or not at all. Without them, the invite answers a
    // join request from the connector, so the keys are already on the connector's machine.
    let has_mtls_key = files.contains(&InviteFile::MtlsKey);
    let has_signing_key = files.contains(&InviteFile::EventSigningKey);
    match invite {
        Invite::Producer(_) if has_mtls_key != has_signing_key => Err(InviteError::FileSet(
            "a producer invite holds both private keys or neither",
        )),
        Invite::Consumer(_) if has_signing_key => Err(InviteError::FileSet(
            "a consumer invite holds no event signing key",
        )),
        _ => Ok(()),
    }
}

/// An invite whose signature, checksums and contents passed, unpacked into a folder.
#[derive(Debug)]
pub struct CheckedInvite {
    invite: Invite,
    dir: PathBuf,
    files: BTreeSet<InviteFile>,
}

impl CheckedInvite {
    /// Checks the invite at `invite_path` and unpacks it into `dir`, which must not exist yet.
    /// Nothing is written unless every check passes.
    pub fn open(invite_path: &Path, dir: &Path) -> Result<Self, InviteError> {
        const MAX_MEMBER_BYTES: u64 = 1 << 20;
        let file = File::open(invite_path).map_err(InviteError::io(format!(
            "opening {}",
            invite_path.display()
        )))?;
        let not_a_tar = |source| InviteError::NotATar {
            path: invite_path.to_path_buf(),
            source,
        };

        let mut members: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        let mut archive = tar::Archive::new(file);
        for entry in archive.entries().map_err(not_a_tar)? {
            let mut entry = entry.map_err(not_a_tar)?;
            let name = String::from_utf8_lossy(&entry.path_bytes()).into_owned();
            if !entry.header().entry_type().is_file() {
                return Err(InviteError::UnexpectedMember(name));
            }
            if entry.size() > MAX_MEMBER_BYTES {
                return Err(InviteError::MemberTooLarge(name));
            }
            let mut bytes = Vec::with_capacity(entry.size() as usize);
            entry
                .read_to_end(&mut bytes)
                .map_err(InviteError::io(format!("reading {name} from the invite")))?;
            if members.insert(name.clone(), bytes).is_some() {
                return Err(InviteError::DuplicateMember(name));
            }
        }

        let manifest_json = members
            .remove(MANIFEST)
            .ok_or(InviteError::MissingMember(MANIFEST))?;
        let manifest_sig = members
            .remove(MANIFEST_SIG)
            .ok_or(InviteError::MissingMember(MANIFEST_SIG))?;
        let mut contents: BTreeMap<InviteFile, Vec<u8>> = BTreeMap::new();
        for (name, bytes) in members {
            let Some(file) = InviteFile::ALL
                .into_iter()
                .find(|f| f.member_name() == name)
            else {
                return Err(InviteError::UnexpectedMember(name));
            };
            contents.insert(file, bytes);
        }

        let egress_pub =
            contents
                .get(&InviteFile::EgressPublicKey)
                .ok_or(InviteError::MissingMember(
                    InviteFile::EgressPublicKey.member_name(),
                ))?;
        let egress_key = hex_array::<32>(egress_pub)
            .and_then(|bytes| VerifyingKey::from_bytes(&bytes).ok())
            .ok_or(InviteError::Malformed(
                InviteFile::EgressPublicKey.member_name(),
            ))?;
        let signature = hex_array::<64>(&manifest_sig)
            .map(|bytes| Signature::from_bytes(&bytes))
            .ok_or(InviteError::Malformed(MANIFEST_SIG))?;
        egress_key
            .verify(&[SIGNATURE_DOMAIN, &manifest_json].concat(), &signature)
            .map_err(|_| InviteError::BadSignature)?;

        // The format is read on its own first, so a newer invite is reported as newer.
        #[derive(Deserialize)]
        struct FormatOnly {
            format: u32,
        }
        let FormatOnly { format } = serde_json::from_slice(&manifest_json)?;
        if format > FORMAT {
            return Err(InviteError::NewerFormat(format));
        }
        if format < FORMAT {
            return Err(InviteError::OlderFormat(format));
        }
        let manifest: Manifest = serde_json::from_slice(&manifest_json)?;

        for (name, expected) in &manifest.files {
            let Some(file) = InviteFile::ALL
                .into_iter()
                .find(|f| f.member_name() == name)
            else {
                return Err(InviteError::UnexpectedMember(name.clone()));
            };
            let bytes = contents
                .get(&file)
                .ok_or(InviteError::MissingMember(file.member_name()))?;
            if hex::encode(Sha256::digest(bytes)) != *expected {
                return Err(InviteError::Checksum(file.member_name()));
            }
        }
        if let Some(unlisted) = contents
            .keys()
            .find(|f| !manifest.files.contains_key(f.member_name()))
        {
            return Err(InviteError::Unlisted(unlisted.member_name()));
        }
        let files: BTreeSet<InviteFile> = contents.keys().copied().collect();
        check_file_set(&manifest.invite, &files)?;

        DirBuilder::new()
            .mode(0o700)
            .create(dir)
            .map_err(InviteError::io(format!("creating {}", dir.display())))?;
        for (file, bytes) in &contents {
            let path = dir.join(file.member_name());
            let mode = if file.is_secret() { 0o600 } else { 0o644 };
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(mode)
                .open(&path)
                .and_then(|mut f| f.write_all(bytes))
                .map_err(InviteError::io(format!("writing {}", path.display())))?;
        }

        Ok(CheckedInvite {
            invite: manifest.invite,
            dir: dir.to_path_buf(),
            files,
        })
    }

    pub fn invite(&self) -> &Invite {
        &self.invite
    }

    /// The unpacked file, or `None` when the invite does not hold it.
    pub fn file(&self, file: InviteFile) -> Option<PathBuf> {
        self.files
            .contains(&file)
            .then(|| self.dir.join(file.member_name()))
    }

    /// True when the invite holds private keys, which makes the invite file a secret too.
    pub fn carries_secrets(&self) -> bool {
        self.files.iter().any(|f| f.is_secret())
    }
}

/// Writes a signed invite to `out`, which must not exist yet. `files` are the invite's files
/// other than `egress.pub`. `sign` signs with the egress key, so the key never has to be in
/// memory here.
pub fn write(
    invite: &Invite,
    files: &[(InviteFile, &Path)],
    egress_public_key: &VerifyingKey,
    sign: impl FnOnce(&[u8]) -> Result<[u8; 64], String>,
    out: &Path,
) -> Result<(), InviteError> {
    let mut contents: BTreeMap<InviteFile, Vec<u8>> = BTreeMap::new();
    contents.insert(
        InviteFile::EgressPublicKey,
        hex::encode(egress_public_key.as_bytes()).into_bytes(),
    );
    for &(file, path) in files {
        let bytes =
            std::fs::read(path).map_err(InviteError::io(format!("reading {}", path.display())))?;
        if contents.insert(file, bytes).is_some() {
            return Err(InviteError::DuplicateMember(file.member_name().to_owned()));
        }
    }
    check_file_set(invite, &contents.keys().copied().collect())?;

    let manifest = Manifest {
        format: FORMAT,
        invite: invite.clone(),
        files: contents
            .iter()
            .map(|(file, bytes)| {
                (
                    file.member_name().to_owned(),
                    hex::encode(Sha256::digest(bytes)),
                )
            })
            .collect(),
    };
    let manifest_json = serde_json::to_vec_pretty(&manifest)?;
    let signed = [SIGNATURE_DOMAIN, &manifest_json].concat();
    let signature = Signature::from_bytes(&sign(&signed).map_err(InviteError::Sign)?);
    egress_public_key
        .verify(&signed, &signature)
        .map_err(|_| InviteError::SignedWithAnotherKey)?;
    let signature_hex = hex::encode(signature.to_bytes());

    let mut tar = tar::Builder::new(Vec::new());
    let members = [
        (MANIFEST, manifest_json.as_slice(), false),
        (MANIFEST_SIG, signature_hex.as_bytes(), false),
    ]
    .into_iter()
    .chain(
        contents
            .iter()
            .map(|(file, bytes)| (file.member_name(), bytes.as_slice(), file.is_secret())),
    );
    for (name, bytes, secret) in members {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(if secret { 0o600 } else { 0o644 });
        tar.append_data(&mut header, name, bytes)
            .map_err(InviteError::io(format!("adding {name} to the invite")))?;
    }
    let tar_bytes = tar
        .into_inner()
        .map_err(InviteError::io("finishing the invite tar".to_owned()))?;

    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(out)
        .and_then(|mut f| f.write_all(&tar_bytes))
        .map_err(InviteError::io(format!("writing {}", out.display())))
}

fn hex_array<const N: usize>(text: &[u8]) -> Option<[u8; N]> {
    hex::decode(text.trim_ascii()).ok()?.try_into().ok()
}

#[derive(Debug, thiserror::Error)]
pub enum InviteError {
    #[error("{what}")]
    Io {
        what: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{} is not an invite", path.display())]
    NotATar {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invite member {0:?} is not a file an invite holds")]
    UnexpectedMember(String),
    #[error("invite member {0:?} appears more than once")]
    DuplicateMember(String),
    #[error("invite member {0:?} is larger than any invite file")]
    MemberTooLarge(String),
    #[error("the invite has no {0}")]
    MissingMember(&'static str),
    #[error("{0} in the invite is malformed")]
    Malformed(&'static str),
    #[error(
        "the manifest signature does not match the invite's egress.pub: the invite was \
         changed after it was made, get a new one"
    )]
    BadSignature,
    #[error("the invite is format {0} and this tool reads format {FORMAT}: update this tool")]
    NewerFormat(u32),
    #[error("the invite is format {0} and this tool reads format {FORMAT}: ask for a new invite")]
    OlderFormat(u32),
    #[error("the invite's manifest is not valid")]
    Manifest(#[from] serde_json::Error),
    #[error(
        "{0} does not match its checksum in the manifest: the invite is corrupt, get a new one"
    )]
    Checksum(&'static str),
    #[error("{0} is in the invite but not in its manifest")]
    Unlisted(&'static str),
    #[error("{0}")]
    FileSet(&'static str),
    #[error("signing the invite with the egress key: {0}")]
    Sign(String),
    #[error("the egress key's signature does not match egress.pub")]
    SignedWithAnotherKey,
    #[error("{id:?} is not a valid connector ID: {reason}")]
    ConnectorId { id: String, reason: &'static str },
    #[error("{0:?} is not a valid connector type: use lowercase letters, digits and hyphens")]
    ConnectorType(String),
}

impl InviteError {
    fn io(what: String) -> impl FnOnce(std::io::Error) -> InviteError {
        move |source| InviteError::Io { what, source }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    const EGRESS_SEED: [u8; 32] = [7; 32];

    fn producer() -> Invite {
        Invite::Producer(ProducerInvite {
            connector_id: ConnectorId::try_from("radar-1".to_owned()).unwrap(),
            connector_type: ConnectorType::try_from("adsb".to_owned()).unwrap(),
            nats_url: "tls://10.0.0.5:4222".into(),
            subject: "ajar.ingest.radar-1".into(),
            entity_types: vec!["mim:".into()],
            ontology_version: None,
            transport: serde_json::json!({"kind": "tcp-client", "connect": "10.0.0.6:30003"})
                .as_object()
                .unwrap()
                .clone(),
        })
    }

    fn consumer() -> Invite {
        Invite::Consumer(ConsumerInvite {
            connector_id: ConnectorId::try_from("ally-feed".to_owned()).unwrap(),
            connector_type: ConnectorType::try_from("tak-egress".to_owned()).unwrap(),
            nats_url: "tls://10.0.0.5:4222".into(),
            egress_subject: "ajar.egress.cot.*".into(),
        })
    }

    /// Writes an invite with `files` into `dir` and returns its path.
    fn write_invite(dir: &Path, invite: &Invite, files: &[InviteFile]) -> PathBuf {
        let sources: Vec<(InviteFile, PathBuf)> = files
            .iter()
            .map(|&file| {
                let path = dir.join(format!("source-{}", file.member_name()));
                std::fs::write(&path, format!("contents of {}", file.member_name())).unwrap();
                (file, path)
            })
            .collect();
        let borrowed: Vec<(InviteFile, &Path)> =
            sources.iter().map(|(f, p)| (*f, p.as_path())).collect();
        let out = dir.join("radar-1.invite");
        let egress_key = SigningKey::from_bytes(&EGRESS_SEED);
        write(
            invite,
            &borrowed,
            &egress_key.verifying_key(),
            |message| Ok(egress_key.sign(message).to_bytes()),
            &out,
        )
        .unwrap();
        out
    }

    const WITH_KEYS: [InviteFile; 4] = [
        InviteFile::CaCert,
        InviteFile::MtlsCert,
        InviteFile::MtlsKey,
        InviteFile::EventSigningKey,
    ];

    fn read_members(path: &Path) -> Vec<(String, Vec<u8>)> {
        let mut archive = tar::Archive::new(File::open(path).unwrap());
        archive
            .entries()
            .unwrap()
            .map(|entry| {
                let mut entry = entry.unwrap();
                let name = entry.path().unwrap().to_string_lossy().into_owned();
                let mut bytes = Vec::new();
                entry.read_to_end(&mut bytes).unwrap();
                (name, bytes)
            })
            .collect()
    }

    fn write_members(path: &Path, members: &[(String, Vec<u8>)]) {
        let mut tar = tar::Builder::new(File::create(path).unwrap());
        for (name, bytes) in members {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            tar.append_data(&mut header, name, bytes.as_slice())
                .unwrap();
        }
        tar.finish().unwrap();
    }

    /// Changes the manifest of the invite at `path` and signs it again with the egress key.
    fn resign(path: &Path, change: impl FnOnce(&mut serde_json::Value)) {
        let mut members = read_members(path);
        let (_, manifest) = members.iter_mut().find(|(n, _)| n == MANIFEST).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(manifest).unwrap();
        change(&mut value);
        *manifest = serde_json::to_vec(&value).unwrap();
        let signature = SigningKey::from_bytes(&EGRESS_SEED)
            .sign(&[SIGNATURE_DOMAIN, manifest.as_slice()].concat());
        let (_, sig) = members.iter_mut().find(|(n, _)| n == MANIFEST_SIG).unwrap();
        *sig = hex::encode(signature.to_bytes()).into_bytes();
        write_members(path, &members);
    }

    #[test]
    fn producer_invite_round_trips_with_private_keys() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_invite(tmp.path(), &producer(), &WITH_KEYS);
        let checked = CheckedInvite::open(&path, &tmp.path().join("open")).unwrap();
        assert_eq!(checked.invite(), &producer());
        assert!(checked.carries_secrets());
        let key = checked.file(InviteFile::EventSigningKey).unwrap();
        assert_eq!(
            std::fs::read_to_string(&key).unwrap(),
            "contents of signing.key"
        );
        let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "private keys are unpacked readable by the owner only"
        );
    }

    #[test]
    fn consumer_invite_without_keys_carries_no_secrets() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_invite(
            tmp.path(),
            &consumer(),
            &[InviteFile::CaCert, InviteFile::MtlsCert],
        );
        let checked = CheckedInvite::open(&path, &tmp.path().join("open")).unwrap();
        assert_eq!(checked.invite(), &consumer());
        assert!(!checked.carries_secrets());
        assert_eq!(checked.file(InviteFile::MtlsKey), None);
    }

    #[test]
    fn changed_manifest_fails_the_signature() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_invite(tmp.path(), &producer(), &WITH_KEYS);
        let mut members = read_members(&path);
        let (_, manifest) = members.iter_mut().find(|(n, _)| n == MANIFEST).unwrap();
        *manifest = String::from_utf8(manifest.clone())
            .unwrap()
            .replace("radar-1", "radar-2")
            .into_bytes();
        write_members(&path, &members);
        let err = CheckedInvite::open(&path, &tmp.path().join("open")).unwrap_err();
        assert!(matches!(err, InviteError::BadSignature), "{err}");
    }

    #[test]
    fn changed_file_fails_its_checksum() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_invite(tmp.path(), &producer(), &WITH_KEYS);
        let mut members = read_members(&path);
        let (_, cert) = members.iter_mut().find(|(n, _)| n == "mtls.crt").unwrap();
        cert.push(b'!');
        write_members(&path, &members);
        let err = CheckedInvite::open(&path, &tmp.path().join("open")).unwrap_err();
        assert!(matches!(err, InviteError::Checksum("mtls.crt")), "{err}");
    }

    #[test]
    fn member_an_invite_does_not_hold_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_invite(tmp.path(), &producer(), &WITH_KEYS);
        let mut members = read_members(&path);
        members.push((
            "radar-1.toml".into(),
            b"connector_id = \"radar-1\"".to_vec(),
        ));
        write_members(&path, &members);
        let err = CheckedInvite::open(&path, &tmp.path().join("open")).unwrap_err();
        assert!(
            matches!(err, InviteError::UnexpectedMember(ref n) if n == "radar-1.toml"),
            "{err}"
        );
        assert!(
            !tmp.path().join("open").exists(),
            "nothing is unpacked from a refused invite"
        );
    }

    #[test]
    fn unknown_manifest_field_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_invite(tmp.path(), &producer(), &WITH_KEYS);
        resign(&path, |m| {
            m["invite"]["spool"] = serde_json::json!("/var/spool/ajar");
        });
        let err = CheckedInvite::open(&path, &tmp.path().join("open")).unwrap_err();
        assert!(matches!(err, InviteError::Manifest(_)), "{err}");
    }

    #[test]
    fn newer_format_asks_to_update_the_tool() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_invite(tmp.path(), &producer(), &WITH_KEYS);
        resign(&path, |m| {
            m["format"] = serde_json::json!(FORMAT + 1);
            m["invite"]["added_later"] = serde_json::json!(true);
        });
        let err = CheckedInvite::open(&path, &tmp.path().join("open")).unwrap_err();
        assert!(matches!(err, InviteError::NewerFormat(_)), "{err}");
    }

    #[test]
    fn producer_with_one_private_key_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let mtls_key = tmp.path().join("mtls.key");
        std::fs::write(&mtls_key, "key").unwrap();
        let ca = tmp.path().join("ca.crt");
        std::fs::write(&ca, "ca").unwrap();
        let files = [
            (InviteFile::CaCert, ca.as_path()),
            (InviteFile::MtlsCert, ca.as_path()),
            (InviteFile::MtlsKey, mtls_key.as_path()),
        ];
        let out = tmp.path().join("radar-1.invite");
        let egress_key = SigningKey::from_bytes(&EGRESS_SEED);
        let err = write(
            &producer(),
            &files,
            &egress_key.verifying_key(),
            |message| Ok(egress_key.sign(message).to_bytes()),
            &out,
        )
        .unwrap_err();
        assert!(matches!(err, InviteError::FileSet(_)), "{err}");
        assert!(
            !out.exists(),
            "no invite is written when the file set is wrong"
        );
    }

    #[test]
    fn invite_signed_by_another_key_is_not_written() {
        let tmp = tempfile::tempdir().unwrap();
        let ca = tmp.path().join("ca.crt");
        std::fs::write(&ca, "ca").unwrap();
        let files = [
            (InviteFile::CaCert, ca.as_path()),
            (InviteFile::MtlsCert, ca.as_path()),
        ];
        let out = tmp.path().join("ally-feed.invite");
        let other_key = SigningKey::from_bytes(&[8; 32]);
        let err = write(
            &consumer(),
            &files,
            &SigningKey::from_bytes(&EGRESS_SEED).verifying_key(),
            |message| Ok(other_key.sign(message).to_bytes()),
            &out,
        )
        .unwrap_err();
        assert!(matches!(err, InviteError::SignedWithAnotherKey), "{err}");
        assert!(!out.exists());
    }

    #[test]
    fn connector_id_refuses_reserved_and_malformed_names() {
        for bad in ["ajar-core", "Radar-1", "-radar", "radar-", "", "radar_1"] {
            assert!(
                ConnectorId::try_from(bad.to_owned()).is_err(),
                "{bad:?} should be refused"
            );
        }
        assert!(ConnectorId::try_from("radar-1".to_owned()).is_ok());
    }
}
