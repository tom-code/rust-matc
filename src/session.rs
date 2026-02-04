use aes::cipher::crypto_common;
use byteorder::{LittleEndian, WriteBytesExt};

use crate::{messages, util::cryptoutil};
use anyhow::Result;
use std::io::Write;
use std::sync::atomic::{AtomicU32, Ordering};

pub struct Session {
    pub session_id: u16,
    pub my_session_id: u16,
    counter: AtomicU32,
    pub local_node: Option<Vec<u8>>,
    pub remote_node: Option<Vec<u8>>,
    pub encrypt_key: Option<crypto_common::Key<Aes128Ccm>>,
    pub decrypt_key: Option<crypto_common::Key<Aes128Ccm>>,
}
type Aes128Ccm = ccm::Ccm<aes::Aes128, ccm::consts::U16, ccm::consts::U13>;
impl Session {
    pub fn new() -> Self {
        Self {
            session_id: 0,
            my_session_id: 0,
            counter: AtomicU32::new(rand::random()),
            local_node: Some([0, 0, 0, 0, 0, 0, 0, 0].to_vec()),
            remote_node: None,
            encrypt_key: None,
            decrypt_key: None,
        }
    }
    pub fn set_encrypt_key(&mut self, k: &[u8]) {
        self.encrypt_key = Some(*crypto_common::Key::<Aes128Ccm>::from_slice(k))
    }
    pub fn set_decrypt_key(&mut self, k: &[u8]) {
        self.decrypt_key = Some(*crypto_common::Key::<Aes128Ccm>::from_slice(k))
    }

    pub fn encode_message(&self, data: &[u8]) -> Result<Vec<u8>> {
        let counter = self.counter.fetch_add(1, Ordering::Relaxed);
        let mg = messages::MessageHeader {
            flags: 0,
            security_flags: 0,
            session_id: self.session_id,
            message_counter: counter,
            source_node_id: self.local_node.clone(),
            destination_node_id: self.remote_node.clone(),
        };
        let mut b = mg.encode()?;
        match self.encrypt_key {
            Some(key) => {
                let nonce = self.make_nonce3(counter)?;
                let enc = cryptoutil::aes128_ccm_encrypt(&key, &nonce, &b, data)?;
                b.extend_from_slice(&enc);
            }
            None => b.extend_from_slice(data),
        };

        Ok(b)
    }

    pub fn decode_message(&self, data: &[u8]) -> Result<Vec<u8>> {
        if self.decrypt_key.is_none() {
            return Ok(data.to_vec());
        }
        let (header, rest) = messages::MessageHeader::decode(data)?;
        if header.session_id != self.my_session_id {
            anyhow::bail!(
                "session id mismatch. expected:{} got:{}",
                self.my_session_id,
                header.session_id
            );
        }
        log::trace!("decode msg header:{:?} session:{}", header, self.session_id);
        let nonce = Self::make_nonce3_extern(header.message_counter, self.remote_node.as_deref())?;
        let add = &data[..data.len() - rest.len()];
        let decoded = cryptoutil::aes128_ccm_decrypt(
            &self.decrypt_key.unwrap_or_default(),
            &nonce,
            add,
            &rest,
        )?;
        let mut out = Vec::new();
        out.extend_from_slice(add);
        out.extend_from_slice(&decoded);
        Ok(out)
    }

    fn make_nonce3(&self, counter: u32) -> Result<Vec<u8>> {
        Self::make_nonce3_extern(counter, self.local_node.as_deref())
    }

    fn make_nonce3_extern(counter: u32, node: Option<&[u8]>) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(128);
        out.write_u8(0)?;
        out.write_u32::<LittleEndian>(counter)?;
        match node {
            Some(s) => out.write_all(s)?,
            None => out.write_all(&[0, 0, 0, 0, 0, 0, 0, 0])?,
        };

        Ok(out)
    }
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}
