// SPDX-License-Identifier: Apache-2.0
//! A test machine with adsb 0.6.7 installed, and invites and requests for it, shared by the
//! instance and command tests.

use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use ajar_tooling::invite::{ConnectorId, ConnectorType, Invite, InviteFile, ProducerInvite};
use ajar_tooling::request::RequestKeys;
use ed25519_dalek::{Signer, SigningKey};
use rcgen::KeyPair;

use crate::connectors::ConnectorVersion;
use crate::context::{Root, Scope};
use crate::instances::{store_request_keys, Instance, StagedInstance};

pub struct Machine {
    pub tmp: tempfile::TempDir,
    pub root: Root,
}

pub fn machine() -> Machine {
    let tmp = tempfile::tempdir().unwrap();
    let root = Root::create(&tmp.path().join("root"), Scope::CurrentUser).unwrap();
    let version_dir = root.connectors_dir().join("adsb/0.6.7");
    std::fs::create_dir_all(&version_dir).unwrap();
    let binary = version_dir.join("ajar-adsb");
    std::fs::write(&binary, b"binary").unwrap();
    std::fs::set_permissions(&binary, Permissions::from_mode(0o755)).unwrap();
    Machine { tmp, root }
}

pub fn create(
    root: &Root,
    invite: &Path,
    version: ConnectorVersion,
    target: Option<String>,
    settings: Option<&Path>,
) -> anyhow::Result<Instance> {
    let mut staged = StagedInstance::stage(root, invite)?;
    staged.prepare(root, version, target, settings)?;
    staged.commit()
}

pub fn producer() -> Invite {
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

/// Writes an invite with private keys into the machine's temp folder.
pub fn write_invite(machine: &Machine, invite: &Invite) -> PathBuf {
    let mut files = vec![
        InviteFile::CaCert,
        InviteFile::MtlsCert,
        InviteFile::MtlsKey,
    ];
    if matches!(invite, Invite::Producer(_)) {
        files.push(InviteFile::EventSigningKey);
    }
    let sources: Vec<(InviteFile, PathBuf)> = files
        .into_iter()
        .map(|file| {
            let path = machine.tmp.path().join(file.member_name());
            std::fs::write(&path, b"contents").unwrap();
            (file, path)
        })
        .collect();
    let borrowed: Vec<(InviteFile, &Path)> =
        sources.iter().map(|(f, p)| (*f, p.as_path())).collect();
    let out = machine
        .tmp
        .path()
        .join(format!("{}.invite", invite.connector_id()));
    let egress_key = SigningKey::from_bytes(&[7; 32]);
    ajar_tooling::invite::write(
        invite,
        &borrowed,
        &egress_key.verifying_key(),
        |message| Ok(egress_key.sign(message).to_bytes()),
        &out,
    )
    .unwrap();
    out
}

/// Writes an invite with no private keys whose certificate is for `mtls_key_pem`.
pub fn write_answer(machine: &Machine, invite: &Invite, mtls_key_pem: &str) -> PathBuf {
    let key = KeyPair::from_pem(mtls_key_pem).unwrap();
    let cert = rcgen::CertificateParams::new(vec![invite.connector_id().to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let ca_path = machine.tmp.path().join("ca.crt");
    let cert_path = machine.tmp.path().join("mtls.crt");
    std::fs::write(&ca_path, cert.pem()).unwrap();
    std::fs::write(&cert_path, cert.pem()).unwrap();
    let out = machine.tmp.path().join("answer.invite");
    let egress_key = SigningKey::from_bytes(&[7; 32]);
    ajar_tooling::invite::write(
        invite,
        &[
            (InviteFile::CaCert, &ca_path),
            (InviteFile::MtlsCert, &cert_path),
        ],
        &egress_key.verifying_key(),
        |message| Ok(egress_key.sign(message).to_bytes()),
        &out,
    )
    .unwrap();
    out
}

pub fn request_keys(machine: &Machine) -> RequestKeys {
    let (_, keys) = ajar_tooling::request::create(
        ajar_tooling::request::Role::Producer,
        producer().connector_id().clone(),
        producer().connector_type().clone(),
    )
    .unwrap();
    store_request_keys(&machine.root, producer().connector_id(), &keys).unwrap();
    keys
}
