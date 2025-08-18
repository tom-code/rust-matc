//! Certificate manager trait and default file based implementation

use std::sync::Arc;

use anyhow::{Context, Result};

use crate::{cert_x509, util::cryptoutil};

pub trait CertManager: Send + Sync {
    fn get_ca_cert(&self) -> Result<Vec<u8>>;
    fn get_ca_key(&self) -> Result<p256::SecretKey>;
    fn get_ca_public_key(&self) -> Result<Vec<u8>>;
    fn get_user_cert(&self, id: u64) -> Result<Vec<u8>>;
    fn get_user_key(&self, id: u64) -> Result<p256::SecretKey>;
    fn get_fabric_id(&self) -> u64;
}

/// Example implementation of [CertManager] trait.
/// It stores keys and certificates in PEM files in specified directory.
pub struct FileCertManager {
    fabric_id: u64,
    path: String,
}

impl FileCertManager {
    pub fn new(fabric_id: u64, path: &str) -> Arc<Self> {
        Arc::new(Self {
            fabric_id,
            path: path.to_owned(),
        })
    }
    pub fn load(path: &str) -> Result<Arc<Self>> {
        let fname = format!("{}/metadata.pem", path);
        let fabric_str =
            std::fs::read_to_string(&fname).context(format!("can't read from {}", fname))?;
        let fabric_id = fabric_str.parse::<u64>()?;
        Ok(Arc::new(Self {
            fabric_id,
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
    fn metadata_fname(&self) -> String {
        format!("{}/metadata.pem", self.path)
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
        std::fs::write(self.metadata_fname(), format!("{}", self.fabric_id))?;
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
}
