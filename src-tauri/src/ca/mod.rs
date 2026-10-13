pub mod install;

use anyhow::{Context, Result};
use dashmap::DashMap;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Ia5String, KeyPair,
    KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

const CA_CERT_FILE: &str = "rootCA.pem";
const CA_KEY_FILE: &str = "rootCA.key";
const CA_COMMON_NAME: &str = "Fake Response Proxy Root CA";
const CA_ORG: &str = "Fake Response Proxy";

/// Root CA + signed leaf cert cache.
#[derive(Debug)]
pub struct CertAuthority {
    storage_dir: PathBuf,
    ca_cert_pem: String,
    ca_cert_der: CertificateDer<'static>,
    /// SNI -> CertifiedKey
    leaf_cache: DashMap<String, Arc<rustls::sign::CertifiedKey>>,
}

impl CertAuthority {
    /// Load CA from `storage_dir`, or create one if missing.
    pub fn load_or_create(storage_dir: &Path) -> Result<Self> {
        fs::create_dir_all(storage_dir).context("create CA storage dir")?;

        let cert_path = storage_dir.join(CA_CERT_FILE);
        let key_path = storage_dir.join(CA_KEY_FILE);

        let (ca_cert_pem, ca_key_pem) = if cert_path.exists() && key_path.exists() {
            (
                fs::read_to_string(&cert_path).context("read CA cert")?,
                fs::read_to_string(&key_path).context("read CA key")?,
            )
        } else {
            let (cert_pem, key_pem) = generate_ca()?;
            fs::write(&cert_path, &cert_pem).context("write CA cert")?;
            fs::write(&key_path, &key_pem).context("write CA key")?;
            (cert_pem, key_pem)
        };

        // Parse once to validate; reparsed lazily in generate_leaf.
        let _ = KeyPair::from_pem(&ca_key_pem).context("parse CA key")?;

        let ca_cert_der = {
            let mut reader = ca_cert_pem.as_bytes();
            let mut certs = rustls_pemfile::certs(&mut reader)
                .collect::<std::result::Result<Vec<_>, _>>()
                .context("parse CA cert PEM")?;
            certs
                .pop()
                .ok_or_else(|| anyhow::anyhow!("no cert in CA PEM"))?
        };

        Ok(Self {
            storage_dir: storage_dir.to_path_buf(),
            ca_cert_pem,
            ca_cert_der,
            leaf_cache: DashMap::new(),
        })
    }

    pub fn ca_cert_path(&self) -> PathBuf {
        self.storage_dir.join(CA_CERT_FILE)
    }

    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// SHA-1 fingerprint of the CA certificate (40 uppercase hex chars).
    /// Used to look up whether this exact cert is installed in a Windows store.
    pub fn sha1_thumbprint(&self) -> String {
        use sha1::{Digest, Sha1};
        let hash = Sha1::digest(self.ca_cert_der.as_ref());
        hex::encode_upper(hash)
    }

    pub fn common_name() -> &'static str {
        CA_COMMON_NAME
    }

    /// Get (or create) a leaf cert for the given SNI hostname.
    pub fn cert_for(&self, sni: &str) -> Result<Arc<rustls::sign::CertifiedKey>> {
        if let Some(c) = self.leaf_cache.get(sni) {
            return Ok(c.clone());
        }
        let ck = self.generate_leaf(sni)?;
        let arc = Arc::new(ck);
        self.leaf_cache.insert(sni.to_string(), arc.clone());
        Ok(arc)
    }

    /// Returns (cn, sans) for the given key.
    fn cn_and_sans_for(sni: &str) -> Result<(String, Vec<SanType>)> {
        if sni == "__local__" {
            return Ok((
                "localhost".to_string(),
                vec![
                    SanType::DnsName(Ia5String::try_from("localhost".to_string())?),
                    SanType::IpAddress("127.0.0.1".parse()?),
                    SanType::IpAddress("::1".parse()?),
                ],
            ));
        }
        if let Ok(ip) = sni.parse::<std::net::IpAddr>() {
            return Ok((sni.to_string(), vec![SanType::IpAddress(ip)]));
        }
        Ok((
            sni.to_string(),
            vec![SanType::DnsName(Ia5String::try_from(sni.to_string())?)],
        ))
    }

    fn generate_leaf(&self, sni: &str) -> Result<rustls::sign::CertifiedKey> {
        // Re-parse CA from PEM each time (cheap; once per new domain).
        let ca_kp = KeyPair::from_pem(
            &fs::read_to_string(self.storage_dir.join(CA_KEY_FILE)).context("read CA key")?,
        )
        .context("parse CA key")?;
        let ca_params = {
            let mut p = CertificateParams::new(vec![CA_COMMON_NAME.to_string()])?;
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, CA_COMMON_NAME);
            dn.push(DnType::OrganizationName, CA_ORG);
            p.distinguished_name = dn;
            p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            p.key_usages = vec![
                KeyUsagePurpose::KeyCertSign,
                KeyUsagePurpose::CrlSign,
                KeyUsagePurpose::DigitalSignature,
            ];
            p
        };
        let ca_cert = ca_params.self_signed(&ca_kp)?;

        let (cn, sans) = Self::cn_and_sans_for(sni)?;

        let mut params = CertificateParams::new(vec![cn.clone()])?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, &cn);
        dn.push(DnType::OrganizationName, CA_ORG);
        params.distinguished_name = dn;
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        ];
        params.subject_alt_names = sans;

        let not_before = SystemTime::now() - Duration::from_secs(60 * 60 * 24);
        let not_after = SystemTime::now() + Duration::from_secs(60 * 60 * 24 * 365 * 2);
        params.not_before = not_before.into();
        params.not_after = not_after.into();

        let leaf_kp = KeyPair::generate()?;
        let leaf_cert = params.signed_by(&leaf_kp, &ca_cert, &ca_kp)?;

        let leaf_der = CertificateDer::from(leaf_cert.der().to_vec());
        let ca_der = self.ca_cert_der.clone();
        let leaf_key_der: PrivateKeyDer<'static> =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_kp.serialize_der()));

        let signing_key =
            rustls::crypto::ring::sign::any_supported_type(&leaf_key_der).context("leaf key")?;
        Ok(rustls::sign::CertifiedKey::new(
            vec![leaf_der, ca_der],
            signing_key,
        ))
    }
}

fn generate_ca() -> Result<(String, String)> {
    let key_pair = KeyPair::generate()?;
    let mut params = CertificateParams::new(vec![CA_COMMON_NAME.to_string()])?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, CA_COMMON_NAME);
    dn.push(DnType::OrganizationName, CA_ORG);
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let not_before = SystemTime::now() - Duration::from_secs(60 * 60 * 24);
    let not_after = SystemTime::now() + Duration::from_secs(60 * 60 * 24 * 365 * 10);
    params.not_before = not_before.into();
    params.not_after = not_after.into();

    let cert = params.self_signed(&key_pair)?;
    Ok((cert.pem(), key_pair.serialize_pem()))
}
