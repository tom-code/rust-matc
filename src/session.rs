use aes::cipher::crypto_common;
use byteorder::{LittleEndian, WriteBytesExt};
use ccm::{aead::Aead, KeyInit};
use crypto_bigint::generic_array::GenericArray;

use crate::messages::{self, MessageHeader};
use std::io::Write;
use anyhow::Result;

pub struct Session {
    pub session_id: u16,
    pub counter: u32,
    pub local_node: Vec<u8>,
    pub remote_node: Vec<u8>,
    pub encrypt_key: Vec<u8>,
    pub decrypt_key: Vec<u8>,
}
type Aes128Ccm = ccm::Ccm<aes::Aes128, ccm::consts::U16, ccm::consts::U13>;
impl Session {
    pub fn new() -> Self {
        Self {
            session_id: 0,
            counter: 0,
            local_node: [0,0,0,0,0,0,0,0].to_vec(),
            remote_node: Vec::new(),
            encrypt_key: Vec::new(),
            decrypt_key: Vec::new()
        }
    }

    pub fn encode_message(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let mg = messages::MessageHeader {
            flags: 0,
            security_flags: 0,
            session_id: self.session_id,
            message_counter: self.counter,
            source_node_id: self.local_node.clone(),
            destination_node_id: self.remote_node.clone(),
        };
        let mut b = mg.encode()?;
        if self.encrypt_key.is_empty() {
            b.extend_from_slice(data);
        } else {
            let nonce = self.make_nonce3()?;
            let key = crypto_common::Key::<Aes128Ccm>::from_slice(&self.encrypt_key);
            let cipher = Aes128Ccm::new(key);
            let enc = match cipher.encrypt(GenericArray::from_slice(&nonce),
                                              ccm::aead::Payload{ msg: data, aad: &b }) {
                                                Ok(o) => o,
                                                Err(e) => return Err(anyhow::anyhow!("encrypt error {:?}", e))
                                                                                          };
            b.extend_from_slice(&enc);
        }
        self.counter+=1;
        Ok(b)
    }

    pub fn decode_message(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if self.decrypt_key.is_empty() {
            return Ok(data.to_vec())
        }
        let (header, rest) = MessageHeader::decode(data)?;
        let nonce = Self::make_nonce3_extern(header.message_counter, &self.remote_node)?;
        let add = &data[..data.len()-rest.len()];
        let key = crypto_common::Key::<Aes128Ccm>::from_slice(&self.decrypt_key);
        let cipher = Aes128Ccm::new(key);
        let decoded = match cipher.decrypt(GenericArray::from_slice(&nonce), ccm::aead::Payload { msg: &rest, aad: add }) {
            Ok(o) => o,
            Err(e) => return Err(anyhow::anyhow!(format!("decrypt error {:?}", e))),
        };
        let mut out = Vec::new();
        out.extend_from_slice(add);
        out.extend_from_slice(&decoded);
        Ok(out)
    }

    fn make_nonce3(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(128);
        out.write_u8(0)?;
        out.write_u32::<LittleEndian>(self.counter)?;
        out.write_all(&self.local_node)?;
        Ok(out)
    }

    fn make_nonce3_extern(counter: u32, node: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(128);
        out.write_u8(0)?;
        out.write_u32::<LittleEndian>(counter)?;
        if !node.is_empty() {
            out.write_all(node)?;
        } else {
            out.write_all(&[0,0,0,0,0,0,0,0])?;
        }
        Ok(out)
    }
}