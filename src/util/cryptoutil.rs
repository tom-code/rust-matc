#![allow(dead_code)]

use aes::cipher::crypto_common;
use anyhow::Result;

use hmac::Mac;
use sha1::Sha1;
use sha2::{Digest, Sha256};

pub fn hkdf_sha256(salt: &[u8], secret: &[u8], info: &[u8], size: usize) -> Result<Vec<u8>> {
    let hk = hkdf::Hkdf::<Sha256>::new(Some(salt), secret);
    let mut okm = vec![0u8; size];
    match hk.expand(info, &mut okm) {
        Ok(()) => Ok(okm),
        Err(e) => Err(anyhow::anyhow!(format!("hkdf error {:?}", e))),
    }
}

pub fn hmac_sha256(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if let Ok(mut hm) = hmac::Hmac::<Sha256>::new_from_slice(key) {
        hm.update(data);
        Ok(hm.finalize().into_bytes().to_vec())
    } else {
        Err(anyhow::anyhow!(format!("can't create hmac {:?}", key)))
    }
}

pub fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}
pub fn sha1_enc(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

type Aes128Ccm = ccm::Ccm<aes::Aes128, ccm::consts::U16, ccm::consts::U13>;
pub fn aes128_ccm_encrypt(
    key: &crypto_common::Key<Aes128Ccm>,
    nonce: &[u8],
    aad: &[u8],
    msg: &[u8],
) -> Result<Vec<u8>> {
    let cipher = <Aes128Ccm as ccm::KeyInit>::new(key);
    match ccm::aead::Aead::encrypt(
        &cipher,
        crypto_common::generic_array::GenericArray::from_slice(nonce),
        ccm::aead::Payload { msg, aad },
    ) {
        Ok(o) => Ok(o),
        Err(e) => Err(anyhow::anyhow!("encrypt error {:?}", e)),
    }
}

pub fn aes128_ccm_decrypt(
    key: &crypto_common::Key<Aes128Ccm>,
    nonce: &[u8],
    aad: &[u8],
    msg: &[u8],
) -> Result<Vec<u8>> {
    let cipher = <Aes128Ccm as ccm::KeyInit>::new(key);
    match ccm::aead::Aead::decrypt(
        &cipher,
        crypto_common::generic_array::GenericArray::from_slice(nonce),
        ccm::aead::Payload { msg, aad },
    ) {
        Ok(o) => Ok(o),
        Err(e) => Err(anyhow::anyhow!(format!("decrypt error {:?}", e))),
    }
}

pub fn read_private_key_from_pem(fname: &str) -> Result<p256::SecretKey> {
    let file_contents = std::fs::read_to_string(fname)?;
    Ok(p256::SecretKey::from_sec1_pem(&file_contents)?)
}
pub fn read_private_key_bytes_from_pem(fname: &str) -> Result<Vec<u8>> {
    let file_contents = std::fs::read_to_string(fname)?;
    Ok(pem::parse(file_contents)?.contents().to_vec())
}

pub fn read_signing_key_from_pem(fname: &str) -> Result<ecdsa::SigningKey<p256::NistP256>> {
    let file_contents = std::fs::read_to_string(fname)?;
    Ok(ecdsa::SigningKey::from(p256::SecretKey::from_sec1_pem(
        &file_contents,
    )?))
}

pub fn read_pub_key_from_pem(fname: &str) -> Result<Vec<u8>> {
    let file_contents = std::fs::read_to_string(fname)?;
    let secretkey = p256::SecretKey::from_sec1_pem(&file_contents)?;
    Ok(secretkey.public_key().to_sec1_bytes().to_vec())
}

pub fn read_data_from_pem(fname: &str) -> Result<Vec<u8>> {
    let file_contents = std::fs::read_to_string(fname)?;
    Ok(pem::parse(file_contents)?.contents().to_vec())
}

pub fn write_pem(tag: &str, data: &[u8], fname: &str) -> Result<()> {
    let p = pem::Pem::new(tag, data);
    let enc = pem::encode(&p);
    std::fs::write(fname, enc)?;
    Ok(())
}

pub fn secret_key_to_rfc5915(key: &p256::SecretKey) -> Result<Vec<u8>> {
    let mut enc = crate::util::asn1::Encoder::new();
    enc.start_seq(0x30)?;
    enc.write_int(1)?;
    enc.write_octet_string(key.to_bytes().as_slice())?;
    enc.start_seq(0xa0)?;
    enc.write_oid("1.2.840.10045.3.1.7")?;
    enc.end_seq();
    enc.start_seq(0xa1)?;
    let mut b: Vec<u8> = vec![0];
    b.extend_from_slice(&key.public_key().to_sec1_bytes());
    enc.write_octet_string_with_tag(0x3, &b)?;
    enc.end_seq();
    enc.end_seq();
    Ok(enc.encode())
}
