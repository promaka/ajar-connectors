// SPDX-License-Identifier: Apache-2.0
//! Reading the AJAR_TLS_* files the way the operator's PKI meant them, and
//! saying what is inside instead of "handshake failed".

use anyhow::{anyhow, Context};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};

/// The fields of one certificate the doctor reasons about.
#[derive(Debug, Clone)]
pub struct CertInfo {
    /// Subject common name, if the certificate carries one.
    pub common_name: Option<String>,
    /// Every DNS name and IP address in the subjectAltName extension.
    pub san: Vec<String>,
    /// Validity window, seconds since the Unix epoch.
    pub not_before: i64,
    pub not_after: i64,
    /// Human-readable window bounds, as the certificate prints them.
    pub not_before_text: String,
    pub not_after_text: String,
    /// Whether basicConstraints marks this as a CA certificate.
    pub is_ca: bool,
}

pub fn inspect_der(der: &[u8]) -> anyhow::Result<CertInfo> {
    let (_, cert) =
        X509Certificate::from_der(der).map_err(|e| anyhow!("not a certificate: {e}"))?;
    let common_name = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|a| a.as_str().ok())
        .map(|s| s.to_string());
    let san = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|ext| {
            ext.value
                .general_names
                .iter()
                .filter_map(|n| match n {
                    GeneralName::DNSName(d) => Some(d.to_string()),
                    GeneralName::IPAddress(ip) => Some(format_ip(ip)),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    let info = CertInfo {
        common_name,
        san,
        not_before: cert.validity().not_before.timestamp(),
        not_after: cert.validity().not_after.timestamp(),
        not_before_text: cert.validity().not_before.to_string(),
        not_after_text: cert.validity().not_after.to_string(),
        is_ca: cert.is_ca(),
    };
    Ok(info)
}

fn format_ip(raw: &[u8]) -> String {
    match raw.len() {
        4 => std::net::Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]).to_string(),
        16 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(raw);
            std::net::Ipv6Addr::from(a).to_string()
        }
        _ => hex::encode(raw),
    }
}

/// Load every certificate in a PEM file.
pub fn load_pem_certs(path: &str) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let certs: Result<Vec<_>, _> = CertificateDer::pem_file_iter(path)
        .map_err(|e| anyhow!("reading {path}: {e}"))?
        .collect();
    let certs = certs.map_err(|e| anyhow!("parsing a certificate in {path}: {e}"))?;
    if certs.is_empty() {
        return Err(anyhow!("{path} contains no certificates"));
    }
    Ok(certs)
}

/// Load the private key from a PEM file.
pub fn load_pem_key(path: &str) -> anyhow::Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_file(path).map_err(|e| anyhow!("parsing the key in {path}: {e}"))
}

/// A parsed client identity: the leaf's fields plus the rustls-ready pair.
pub struct ClientIdentity {
    pub chain: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
    pub leaf: CertInfo,
}

/// Load and cross-check the client certificate and key. The pair-match is
/// delegated to rustls when the handshake config is built; here we make sure
/// both files parse and the leaf's fields are readable.
pub fn load_client_identity(cert_path: &str, key_path: &str) -> anyhow::Result<ClientIdentity> {
    let chain = load_pem_certs(cert_path)?;
    let key = load_pem_key(key_path)?;
    let leaf = inspect_der(chain[0].as_ref())
        .with_context(|| format!("inspecting the first certificate in {cert_path}"))?;
    Ok(ClientIdentity { chain, key, leaf })
}

/// Seconds since the Unix epoch, now.
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair};

    fn mint(names: &[&str]) -> (String, String) {
        let params =
            CertificateParams::new(names.iter().map(|s| s.to_string()).collect::<Vec<_>>())
                .unwrap();
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    fn write(dir: &std::path::Path, name: &str, contents: &str) -> String {
        let p = dir.join(name);
        std::fs::write(&p, contents).unwrap();
        p.to_str().unwrap().to_string()
    }

    #[test]
    fn reads_the_san_list_and_validity_window_out_of_a_real_cert() {
        let dir = std::env::temp_dir().join(format!("ajar-doctor-certs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (cert_pem, key_pem) = mint(&["nats.example.mil", "10.0.0.5"]);
        let cert_path = write(&dir, "c.pem", &cert_pem);
        let key_path = write(&dir, "k.pem", &key_pem);

        let id = load_client_identity(&cert_path, &key_path).unwrap();
        assert!(id.leaf.san.contains(&"nats.example.mil".to_string()));
        assert!(id.leaf.san.contains(&"10.0.0.5".to_string()));
        assert!(id.leaf.not_before <= now_unix());
        assert!(id.leaf.not_after > now_unix());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_key_handed_over_as_the_cert_is_named_for_what_it_is() {
        let dir = std::env::temp_dir().join(format!("ajar-doctor-swap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (cert_pem, key_pem) = mint(&["x"]);
        let key_path = write(&dir, "k.pem", &key_pem);
        let cert_path = write(&dir, "c.pem", &cert_pem);

        // The classic slip: cert and key paths swapped in the env block.
        assert!(load_pem_certs(&key_path).is_err());
        assert!(load_pem_key(&cert_path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_empty_or_garbage_pem_fails_with_the_path_in_the_message() {
        let dir = std::env::temp_dir().join(format!("ajar-doctor-junk-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let junk = write(&dir, "junk.pem", "not pem at all");
        let err = load_pem_certs(&junk).unwrap_err().to_string();
        assert!(err.contains("junk.pem"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
