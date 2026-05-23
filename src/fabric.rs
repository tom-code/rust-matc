use anyhow::Result;

use byteorder::{BigEndian, WriteBytesExt};

pub struct Fabric {
    pub id: u64,
    pub ipk_epoch_key: Vec<u8>,
    pub ca_id: u64,
    ca_public_key: Vec<u8>,
}

impl Fabric {
    /// Create a new Fabric.
    ///
    /// `ipk_epoch_key` is the 16-byte IPK epoch key for this fabric. On the controller side it
    /// should come from [`certmanager::CertManager::get_ipk_epoch_key`] (generated at bootstrap
    /// and persisted in `metadata.json`). On the device side it is supplied by the controller
    /// via AddNOC and stored in `FabricInfo.ipk`.
    pub fn new(fabric_id: u64, ca_id: u64, ca_public_key: &[u8], ipk_epoch_key: &[u8]) -> Self {
        Self {
            id: fabric_id,
            ipk_epoch_key: ipk_epoch_key.to_owned(),
            ca_id,
            ca_public_key: ca_public_key.to_owned(),
        }
    }

    /// Compressed fabric identifier
    pub fn compressed(&self) -> Result<Vec<u8>> {
        let mut buf_id = Vec::new();
        buf_id.write_u64::<BigEndian>(self.id)?;
        crate::util::cryptoutil::hkdf_sha256(
            &buf_id,
            &self.ca_public_key.as_slice()[1..],
            "CompressedFabric".as_bytes(),
            8,
        )
    }

    /// Integrity Protection Key
    pub fn signed_ipk(&self) -> Result<Vec<u8>> {
        crate::util::cryptoutil::hkdf_sha256(
            &self.compressed()?,
            &self.ipk_epoch_key,
            "GroupKey v1.0".as_bytes(),
            16,
        )
    }
}
