// SPDX-License-Identifier: Apache-2.0
//! The request: what `ajar-connectors request` writes and `ajar invite <file>.request` reads. A
//! JSON file with the connector's public keys: a certificate signing request for its mTLS key
//! and, for a producer, its event verifying key. The private keys never leave the connector's
//! machine, so the invite that answers a request holds no private keys.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use ed25519_dalek::{SigningKey, VerifyingKey};
use rcgen::{
    CertificateParams, CertificateSigningRequestParams, DistinguishedName, DnType, KeyPair,
    PublicKey,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::invite::{ConnectorId, ConnectorType};

/// The request format this crate reads and writes. Any other is refused.
pub const FORMAT: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Producer,
    Consumer,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "snake_case")]
pub enum Request {
    Producer(ProducerRequest),
    Consumer(ConsumerRequest),
}

impl Request {
    pub fn connector_id(&self) -> &ConnectorId {
        match self {
            Request::Producer(p) => &p.connector_id,
            Request::Consumer(c) => &c.connector_id,
        }
    }

    pub fn connector_type(&self) -> &ConnectorType {
        match self {
            Request::Producer(p) => &p.connector_type,
            Request::Consumer(c) => &c.connector_type,
        }
    }

    fn csr(&self) -> &str {
        match self {
            Request::Producer(p) => &p.csr,
            Request::Consumer(c) => &c.csr,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProducerRequest {
    pub connector_id: ConnectorId,
    pub connector_type: ConnectorType,
    /// PEM, signed with the mTLS key, asking for `CN=<connector_id>` and nothing else.
    pub csr: String,
    #[serde(serialize_with = "key_to_hex", deserialize_with = "key_from_hex")]
    pub event_verifying_key: VerifyingKey,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumerRequest {
    pub connector_id: ConnectorId,
    pub connector_type: ConnectorType,
    /// PEM, signed with the mTLS key, asking for `CN=<connector_id>` and nothing else.
    pub csr: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestFile {
    format: u32,
    request: Request,
}

/// The private halves of a request's keys, for the caller to store.
pub struct RequestKeys {
    /// PKCS#8 PEM, P-256.
    pub mtls_key_pem: String,
    /// Set for a producer.
    pub event_signing_key: Option<SigningKey>,
}

/// Creates the keys for `connector_id` and the request that carries their public halves.
pub fn create(
    role: Role,
    connector_id: ConnectorId,
    connector_type: ConnectorType,
) -> Result<(Request, RequestKeys), RequestError> {
    let mtls_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let csr = csr_params(&connector_id)
        .serialize_request(&mtls_key)?
        .pem()?;
    let mtls_key_pem = mtls_key.serialize_pem();

    match role {
        Role::Producer => {
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed).map_err(RequestError::Random)?;
            let event_signing_key = SigningKey::from_bytes(&seed);
            let request = Request::Producer(ProducerRequest {
                connector_id,
                connector_type,
                csr,
                event_verifying_key: event_signing_key.verifying_key(),
            });
            let keys = RequestKeys {
                mtls_key_pem,
                event_signing_key: Some(event_signing_key),
            };
            Ok((request, keys))
        }
        Role::Consumer => {
            let request = Request::Consumer(ConsumerRequest {
                connector_id,
                connector_type,
                csr,
            });
            let keys = RequestKeys {
                mtls_key_pem,
                event_signing_key: None,
            };
            Ok((request, keys))
        }
    }
}

/// Writes `request` to `out`, which must not exist yet.
pub fn write(request: &Request, out: &Path) -> Result<(), RequestError> {
    let json = serde_json::to_vec_pretty(&RequestFile {
        format: FORMAT,
        request: request.clone(),
    })?;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(out)
        .and_then(|mut f| f.write_all(&json))
        .map_err(RequestError::io(format!("writing {}", out.display())))
}

/// A request whose format, fields and certificate signing request passed.
#[derive(Debug)]
pub struct CheckedRequest {
    request: Request,
    mtls_public_key: PublicKey,
}

impl CheckedRequest {
    pub fn read(path: &Path) -> Result<Self, RequestError> {
        const MAX_BYTES: u64 = 64 * 1024;
        let mut json = Vec::new();
        File::open(path)
            .and_then(|f| f.take(MAX_BYTES + 1).read_to_end(&mut json))
            .map_err(RequestError::io(format!("reading {}", path.display())))?;
        if json.len() as u64 > MAX_BYTES {
            return Err(RequestError::TooLarge);
        }

        // The format is read on its own first, so a newer request is reported as newer.
        #[derive(Deserialize)]
        struct FormatOnly {
            format: u32,
        }
        let FormatOnly { format } = serde_json::from_slice(&json)?;
        if format > FORMAT {
            return Err(RequestError::NewerFormat(format));
        }
        if format < FORMAT {
            return Err(RequestError::OlderFormat(format));
        }
        let RequestFile { request, .. } = serde_json::from_slice(&json)?;

        let csr = CertificateSigningRequestParams::from_pem(request.csr())?;
        if csr.params != csr_params(request.connector_id()) {
            return Err(RequestError::CsrContents(request.connector_id().clone()));
        }
        if csr.public_key.algorithm() != &rcgen::PKCS_ECDSA_P256_SHA256 {
            return Err(RequestError::CsrKeyType);
        }
        Ok(CheckedRequest {
            request,
            mtls_public_key: csr.public_key,
        })
    }

    pub fn request(&self) -> &Request {
        &self.request
    }

    /// The key the connector's certificate is issued for. The CSR's other contents are checked
    /// and then left out: Core sets the certificate's names, usages and validity itself.
    pub fn mtls_public_key(&self) -> &PublicKey {
        &self.mtls_public_key
    }
}

fn csr_params(connector_id: &ConnectorId) -> CertificateParams {
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, connector_id.as_str());
    params
}

fn key_to_hex<S: Serializer>(key: &VerifyingKey, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&hex::encode(key.as_bytes()))
}

fn key_from_hex<'de, D: Deserializer<'de>>(deserializer: D) -> Result<VerifyingKey, D::Error> {
    use serde::de::Error;
    let text = String::deserialize(deserializer)?;
    let bytes: [u8; 32] = hex::decode(&text)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| D::Error::custom("expected 64 hex characters"))?;
    VerifyingKey::from_bytes(&bytes).map_err(D::Error::custom)
}

#[derive(Debug, thiserror::Error)]
pub enum RequestError {
    #[error("{what}")]
    Io {
        what: String,
        #[source]
        source: std::io::Error,
    },
    #[error("the request is larger than any request file")]
    TooLarge,
    #[error("the request is format {0} and this tool reads format {FORMAT}: update this tool")]
    NewerFormat(u32),
    #[error(
        "the request is format {0} and this tool reads format {FORMAT}: make a new request \
         with an updated ajar-connectors"
    )]
    OlderFormat(u32),
    #[error("the request is not valid")]
    Malformed(#[from] serde_json::Error),
    #[error("the request's certificate signing request is not valid")]
    Csr(#[from] rcgen::Error),
    #[error("the certificate signing request must ask for CN={0} and nothing else")]
    CsrContents(ConnectorId),
    #[error("the certificate signing request must be for a P-256 key")]
    CsrKeyType,
    #[error("no randomness for the event signing key: {0}")]
    Random(getrandom::Error),
}

impl RequestError {
    fn io(what: String) -> impl FnOnce(std::io::Error) -> RequestError {
        move |source| RequestError::Io { what, source }
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, Verifier};
    use rcgen::{BasicConstraints, IsCa, Issuer, PublicKeyData};

    use super::*;

    fn radar() -> (ConnectorId, ConnectorType) {
        (
            ConnectorId::try_from("radar-1".to_owned()).unwrap(),
            ConnectorType::try_from("adsb".to_owned()).unwrap(),
        )
    }

    /// Writes `request` into `dir`, then changes its JSON with `edit` and writes it back.
    fn write_edited(
        dir: &Path,
        request: &Request,
        edit: impl FnOnce(&mut serde_json::Value),
    ) -> std::path::PathBuf {
        let path = dir.join("radar-1.request");
        write(request, &path).unwrap();
        let mut json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        edit(&mut json);
        std::fs::write(&path, serde_json::to_vec(&json).unwrap()).unwrap();
        path
    }

    #[test]
    fn producer_request_round_trips_and_its_keys_match() {
        let (id, connector_type) = radar();
        let (request, keys) = create(Role::Producer, id, connector_type).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("radar-1.request");
        write(&request, &path).unwrap();

        let checked = CheckedRequest::read(&path).unwrap();
        assert_eq!(checked.request(), &request);
        let Request::Producer(p) = checked.request() else {
            panic!("expected a producer request");
        };
        let signing_key = keys.event_signing_key.unwrap();
        let signature = signing_key.sign(b"event");
        assert!(p.event_verifying_key.verify(b"event", &signature).is_ok());

        let mtls_key = KeyPair::from_pem(&keys.mtls_key_pem).unwrap();
        assert_eq!(checked.mtls_public_key().der_bytes(), mtls_key.der_bytes());
    }

    #[test]
    fn consumer_request_has_no_event_key() {
        let (id, connector_type) = radar();
        let (request, keys) = create(Role::Consumer, id, connector_type).unwrap();
        assert!(matches!(request, Request::Consumer(_)));
        assert!(keys.event_signing_key.is_none());
    }

    #[test]
    fn core_can_issue_a_certificate_for_the_request_key() {
        let (id, connector_type) = radar();
        let (request, _) = create(Role::Producer, id, connector_type).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("radar-1.request");
        write(&request, &path).unwrap();
        let checked = CheckedRequest::read(&path).unwrap();

        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let issuer = Issuer::new(ca_params, ca_key);
        let cert = CertificateParams::new(vec!["radar-1".to_owned()])
            .unwrap()
            .signed_by(checked.mtls_public_key(), &issuer)
            .unwrap();
        assert!(cert.pem().contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn csr_for_another_name_is_refused() {
        let (id, connector_type) = radar();
        let (request, _) = create(Role::Consumer, id, connector_type).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let path = write_edited(tmp.path(), &request, |json| {
            json["request"]["connector_id"] = "radar-2".into();
        });
        let err = CheckedRequest::read(&path).unwrap_err();
        assert!(matches!(err, RequestError::CsrContents(_)), "{err}");
    }

    #[test]
    fn csr_asking_for_more_than_its_name_is_refused() {
        let (id, connector_type) = radar();
        let (request, _) = create(Role::Consumer, id.clone(), connector_type).unwrap();
        let mut params = csr_params(&id);
        params.subject_alt_names = vec![rcgen::SanType::DnsName("core".try_into().unwrap())];
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let csr = params.serialize_request(&key).unwrap().pem().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let path = write_edited(tmp.path(), &request, |json| {
            json["request"]["csr"] = csr.into();
        });
        let err = CheckedRequest::read(&path).unwrap_err();
        assert!(matches!(err, RequestError::CsrContents(_)), "{err}");
    }

    #[test]
    fn unknown_field_is_refused() {
        let (id, connector_type) = radar();
        let (request, _) = create(Role::Consumer, id, connector_type).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let path = write_edited(tmp.path(), &request, |json| {
            json["request"]["subject"] = "ajar.ingest.>".into();
        });
        let err = CheckedRequest::read(&path).unwrap_err();
        assert!(matches!(err, RequestError::Malformed(_)), "{err}");
    }

    #[test]
    fn newer_format_asks_to_update() {
        let (id, connector_type) = radar();
        let (request, _) = create(Role::Consumer, id, connector_type).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let path = write_edited(tmp.path(), &request, |json| {
            json["format"] = (FORMAT + 1).into();
        });
        let err = CheckedRequest::read(&path).unwrap_err();
        assert!(matches!(err, RequestError::NewerFormat(_)), "{err}");
    }
}
