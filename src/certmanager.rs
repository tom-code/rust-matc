use anyhow::Result;

use crate::{cert_x509, util::cryptoutil};

pub trait CertManager: Send + Sync {
    fn get_ca_cert(&self) -> Result<Vec<u8>>;
    fn get_ca_key(&self) -> Result<p256::SecretKey>;
    fn get_ca_public_key(&self) -> Result<Vec<u8>>;
    fn get_user_cert(&self, id: u64) -> Result<Vec<u8>>;
    fn get_user_key(&self, id: u64) -> Result<p256::SecretKey>;
}

pub struct FileCertManager {
    fabric_id: u64,
    path: String,
}

impl FileCertManager {
    pub fn new(fabric_id: u64, path: &str) -> Self {
        Self {
            fabric_id,
            path: path.to_owned(),
        }
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
}

const CA_NODE_ID: u64 = 1;

impl FileCertManager {
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
        Ok(())
    }

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
}
