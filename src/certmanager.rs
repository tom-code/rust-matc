use anyhow::Result;

use crate::{cert, cryptoutil};

pub trait CertManager{
    fn bootstrap(&self) -> Result<()>;
    fn create_user(&self, id: u64) -> Result<()>;
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
    pub fn new(fabric_id: u64) -> Self {
        Self {
            fabric_id,
            path: "./pem2".to_owned(),
        }
    }
    fn user_key_fname(id: u64) -> String {
        format!("pem2/{}-private.pem", id)
    }
    fn user_cert_fname(id: u64) -> String {
        format!("pem2/{}-cert.pem", id)
    }
}

const CA_NODE_ID: u64 = 1;
impl CertManager for FileCertManager {
    fn bootstrap(&self) -> Result<()> {
        std::fs::create_dir(&self.path)?;

        let secret_key = p256::SecretKey::random(&mut rand::thread_rng());
        let data = cryptoutil::secret_key_to_rfc5915(&secret_key)?;
        let pem = pem::Pem::new("EC PRIVATE KEY", data);
        std::fs::write("./pem2/ca-private.pem", pem::encode(&pem).as_bytes())?;
        let node_public_key = secret_key.public_key().to_sec1_bytes();

        let x509 = cert::encode_x509(
            &node_public_key,
            CA_NODE_ID,
            self.fabric_id,
            CA_NODE_ID,
            &secret_key,
            true,
        )?;
        cryptoutil::write_pem("CERTIFICATE", &x509, "./pem2/ca-cert.pem")?;
        Ok(())
    }

    fn create_user(&self, id: u64) -> Result<()> {
        let ca_private = self.get_ca_key()?;
        let secret_key = p256::SecretKey::random(&mut rand::thread_rng());
        let data = cryptoutil::secret_key_to_rfc5915(&secret_key)?;
        let pem = pem::Pem::new("EC PRIVATE KEY", data);
        std::fs::write(Self::user_key_fname(id), pem::encode(&pem).as_bytes())?;
        let node_public_key = secret_key.public_key().to_sec1_bytes();

        let x509 = cert::encode_x509(
            &node_public_key,
            id,
            self.fabric_id,
            CA_NODE_ID,
            &ca_private,
            false,
        )?;
        cryptoutil::write_pem("CERTIFICATE", &x509, &Self::user_cert_fname(id))?;
        Ok(())
    }

    fn get_ca_cert(&self) -> Result<Vec<u8>> {
        cryptoutil::read_data_from_pem("./pem2/ca-cert.pem")
    }

    fn get_ca_key(&self) -> Result<p256::SecretKey> {
        cryptoutil::read_private_key_from_pem("./pem2/ca-private.pem")
    }

    fn get_user_cert(&self, id: u64) -> Result<Vec<u8>> {
        cryptoutil::read_data_from_pem(&Self::user_cert_fname(id))
    }

    fn get_user_key(&self, id: u64) -> Result<p256::SecretKey> {
        cryptoutil::read_private_key_from_pem(&Self::user_key_fname(id))
    }

    fn get_ca_public_key(&self) -> Result<Vec<u8>> {
        Ok(self.get_ca_key()?.public_key().to_sec1_bytes().to_vec())
    }
}
