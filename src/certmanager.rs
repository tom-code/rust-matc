//! Certificate manager trait and default file based implementation

use std::sync::Arc;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::{cert_x509, util::cryptoutil};

pub trait CertManager: Send + Sync {
    fn get_ca_cert(&self) -> Result<Vec<u8>>;
    fn get_ca_key(&self) -> Result<p256::SecretKey>;
    fn get_ca_public_key(&self) -> Result<Vec<u8>>;
    fn get_user_cert(&self, id: u64) -> Result<Vec<u8>>;
    fn get_user_key(&self, id: u64) -> Result<p256::SecretKey>;
    fn get_fabric_id(&self) -> u64;
    fn get_ipk_epoch_key(&self) -> Vec<u8>;
}

/// Example implementation of [CertManager] trait.
/// It stores keys and certificates in PEM files in specified directory.
pub struct FileCertManager {
    fabric_id: u64,
    ipk_epoch_key: Vec<u8>,
    path: String,
}

#[derive(Serialize, Deserialize)]
struct Metadata {
    fabric_id: String,
    ipk_epoch_key: String,
}

impl FileCertManager {
    pub fn new(fabric_id: u64, path: &str) -> Arc<Self> {
        let ipk_epoch_key: [u8; 16] = rand::random();
        Arc::new(Self {
            fabric_id,
            ipk_epoch_key: ipk_epoch_key.to_vec(),
            path: path.to_owned(),
        })
    }

    /// Load an existing CA identity from `path`.
    ///
    /// Reads `metadata.json` (fabric_id + ipk_epoch_key) if present.
    /// Falls back to legacy `metadata.pem` (fabric_id only, hardcoded IPK)
    /// so identities bootstrapped before this change keep working.
    pub fn load(path: &str) -> Result<Arc<Self>> {
        let json_path = format!("{}/metadata.json", path);
        let pem_path = format!("{}/metadata.pem", path);

        let (fabric_id, ipk_epoch_key) = if std::path::Path::new(&json_path).exists() {
            let s = std::fs::read_to_string(&json_path)
                .context(format!("can't read from {}", json_path))?;
            let m: Metadata = serde_json::from_str(&s)
                .context(format!("invalid JSON in {}", json_path))?;
            let fid = m.fabric_id.parse::<u64>()
                .context("invalid fabric_id in metadata.json")?;
            let ipk = hex::decode(&m.ipk_epoch_key)
                .context("invalid ipk_epoch_key hex in metadata.json")?;
            (fid, ipk)
        } else {
            let s = std::fs::read_to_string(&pem_path)
                .context(format!("can't read from {}", pem_path))?;
            let fid = s.trim().parse::<u64>()?;
            (fid, vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf])
        };

        Ok(Arc::new(Self {
            fabric_id,
            ipk_epoch_key,
            path: path.to_owned(),
        }))
    }

    fn user_key_fname(&self, id: u64) -> String {
        format!("{}/{}-private.pem", self.path, id)
    }
    fn ca_key_fname(&self) -> String {
        format!("{}/ca-private.pem", self.path)
    }
    fn user_cert_fname(&self, id: u64) -> String {
        format!("{}/{}-cert.pem", self.path, id)
    }
    fn ca_cert_fname(&self) -> String {
        format!("{}/ca-cert.pem", self.path)
    }
    fn metadata_json_fname(&self) -> String {
        format!("{}/metadata.json", self.path)
    }
}

const CA_NODE_ID: u64 = 1;

/*fn extract_fabric_id(fname: &str) -> Result<u64> {
    let x509_raw = cryptoutil::read_data_from_pem(fname)?;
    let x509 = x509_cert::Certificate::from_der(&x509_raw)?;
    let subject = x509.tbs_certificate.subject;
    for rdn in subject.0 {
        for av in rdn.0.as_slice() {
            if av.oid == const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.37244.1.5") {
                let valstr = av.value.decode_as::<String>()?;
                return Ok(u64::from_str_radix(&valstr, 16)?)
            }
        }
    };
    Err(anyhow::anyhow!("can't extract fabric id"))
}*/

impl FileCertManager {
    /// Initialize CA. Create directory, generate CA key and certificate and store them in specified directory.
    /// Also writes `metadata.json` with the fabric_id and a randomly generated IPK epoch key.
    /// Directory must not exist before calling this function. If it exists function will fail.
    pub fn bootstrap(&self) -> Result<()> {
        std::fs::create_dir(&self.path)?;

        let secret_key = p256::SecretKey::random(&mut rand::thread_rng());
        let data = cryptoutil::secret_key_to_rfc5915(&secret_key)?;
        let pem = pem::Pem::new("EC PRIVATE KEY", data);
        std::fs::write(self.ca_key_fname(), pem::encode(&pem).as_bytes())?;
        let node_public_key = secret_key.public_key().to_sec1_bytes();

        let x509 = cert_x509::encode_x509(
            &node_public_key,
            CA_NODE_ID,
            self.fabric_id,
            CA_NODE_ID,
            &secret_key,
            true,
        )?;
        cryptoutil::write_pem("CERTIFICATE", &x509, &self.ca_cert_fname())?;
        let metadata = Metadata {
            fabric_id: format!("{}", self.fabric_id),
            ipk_epoch_key: hex::encode(&self.ipk_epoch_key),
        };
        std::fs::write(
            self.metadata_json_fname(),
            serde_json::to_string_pretty(&metadata)?,
        )?;
        Ok(())
    }

    /// Create key and certificate for specified node identifier.
    /// This can be used as credentials for admin(and any additional) user controlling devices.
    pub fn create_user(&self, id: u64) -> Result<()> {
        let ca_private = self.get_ca_key()?;
        let secret_key = p256::SecretKey::random(&mut rand::thread_rng());
        let data = cryptoutil::secret_key_to_rfc5915(&secret_key)?;
        let pem = pem::Pem::new("EC PRIVATE KEY", data);
        std::fs::write(self.user_key_fname(id), pem::encode(&pem).as_bytes())?;
        let node_public_key = secret_key.public_key().to_sec1_bytes();

        let x509 = cert_x509::encode_x509(
            &node_public_key,
            id,
            self.fabric_id,
            CA_NODE_ID,
            &ca_private,
            false,
        )?;
        cryptoutil::write_pem("CERTIFICATE", &x509, &self.user_cert_fname(id))?;
        Ok(())
    }
}

impl CertManager for FileCertManager {
    fn get_ca_cert(&self) -> Result<Vec<u8>> {
        cryptoutil::read_data_from_pem(&self.ca_cert_fname())
    }

    fn get_ca_key(&self) -> Result<p256::SecretKey> {
        cryptoutil::read_private_key_from_pem(&self.ca_key_fname())
    }

    fn get_user_cert(&self, id: u64) -> Result<Vec<u8>> {
        cryptoutil::read_data_from_pem(&self.user_cert_fname(id))
    }

    fn get_user_key(&self, id: u64) -> Result<p256::SecretKey> {
        cryptoutil::read_private_key_from_pem(&self.user_key_fname(id))
    }

    fn get_ca_public_key(&self) -> Result<Vec<u8>> {
        Ok(self.get_ca_key()?.public_key().to_sec1_bytes().to_vec())
    }

    fn get_fabric_id(&self) -> u64 {
        self.fabric_id
    }

    fn get_ipk_epoch_key(&self) -> Vec<u8> {
        self.ipk_epoch_key.clone()
    }
}
