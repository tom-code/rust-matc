use anyhow::Result;

use byteorder::{BigEndian, WriteBytesExt};

pub struct Fabric {
    pub id: u64,
    pub ipk_epoch_key: Vec<u8>,
    pub ca_id: u64,
    ca_public_key: Vec<u8>,
}

impl Fabric {
    pub fn new(fabric_id: u64, ca_id: u64, ca_public_key: &[u8]) -> Self {
        Self {
            id: fabric_id,
            ipk_epoch_key: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf],
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
