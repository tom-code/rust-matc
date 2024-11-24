use anyhow::Result;

use byteorder::{BigEndian, WriteBytesExt};



pub struct Fabric {
    pub id: u64,
    pub ipk_epoch_key: Vec<u8>,
    pub ca_id: u64
}


impl Fabric {
    pub fn new(id: u64) -> Self {
        Self {
            id,
            ipk_epoch_key: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf],
            ca_id: 1
        }
    }

    pub fn compressed(&self) -> Result<Vec<u8>> {
        let ca_pub = crate::cryptoutil::read_pub_key_from_pem("pem2/ca-private.pem")?;
        let mut buf_id = Vec::new();
        buf_id.write_u64::<BigEndian>(self.id)?;
        crate::cryptoutil::hkdf_sha256(&buf_id, &ca_pub[1..], "CompressedFabric".as_bytes(), 8)
    }

    pub fn signed_ipk(&self) -> Result<Vec<u8>> {
        crate::cryptoutil::hkdf_sha256(&self.compressed()?, &self.ipk_epoch_key, "GroupKey v1.0".as_bytes(), 16)
    }
}