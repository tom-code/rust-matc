use std::io::Write;

use crate::{fabric, tlv, util::cryptoutil};
use anyhow::Result;
use byteorder::{LittleEndian, WriteBytesExt};
use ccm::{aead::Aead, KeyInit};

pub struct SigmaContext {
    pub sigma1_payload: Vec<u8>,
    pub sigma2_payload: Vec<u8>,
    pub sigma3_payload: Vec<u8>,
    pub session_id: u16,
    eph_key: p256::ecdh::EphemeralSecret,
    pub node_id: u64,
    pub responder_public: Vec<u8>,
    pub responder_session: u16,
    pub shared: Option<p256::ecdh::SharedSecret>,
}

impl SigmaContext {
    pub fn new(node_id: u64) -> Self {
        Self {
            sigma1_payload: Vec::new(),
            sigma2_payload: Vec::new(),
            sigma3_payload: Vec::new(),
            session_id: rand::random(),
            eph_key: p256::ecdh::EphemeralSecret::random(&mut rand::thread_rng()),
            node_id,
            responder_public: Vec::new(),
            responder_session: 0,
            shared: None,
        }
    }
}

pub fn sigma1(fabric: &fabric::Fabric, ctx: &mut SigmaContext, ca_pubkey: &[u8]) -> Result<()> {
    let mut initator_random = [0; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut initator_random);

    // send sigma1
    let mut tlv = tlv::TlvBuffer::new();
    tlv.write_anon_struct()?;
    tlv.write_octetstring(1, &initator_random)?;

    tlv.write_uint16(2, ctx.session_id)?;
    let mut dst = Vec::new();
    dst.write_all(&initator_random)?;
    dst.write_all(ca_pubkey)?;
    dst.write_u64::<LittleEndian>(fabric.id)?;
    dst.write_u64::<LittleEndian>(ctx.node_id)?;

    let dst_id = cryptoutil::hmac_sha256(&dst, &fabric.signed_ipk()?)?;
    tlv.write_octetstring(3, &dst_id)?;
    tlv.write_octetstring(4, &ctx.eph_key.public_key().to_sec1_bytes())?;
    tlv.write_struct_end()?;
    ctx.sigma1_payload = tlv.data.clone();
    Ok(())
}

type Aes128Ccm = ccm::Ccm<aes::Aes128, ccm::consts::U16, ccm::consts::U13>;

pub fn sigma3(
    fabric: &fabric::Fabric,
    ctx: &mut SigmaContext,
    ctrl_private_key: &[u8],
    ctrl_matter_cert: &[u8],
) -> Result<()> {
    let ctrl_key = p256::SecretKey::from_sec1_der(ctrl_private_key)?;
    let ctrl_key = ecdsa::SigningKey::from(ctrl_key);

    let tbs = {
        let mut tlv = tlv::TlvBuffer::new();
        tlv.write_anon_struct()?;
        tlv.write_octetstring(1, ctrl_matter_cert)?;
        tlv.write_octetstring(3, &ctx.eph_key.public_key().to_sec1_bytes())?;
        tlv.write_octetstring(4, &ctx.responder_public)?;
        tlv.write_struct_end()?;
        let sig = ctrl_key.sign_recoverable(&tlv.data)?.0;
        sig.to_bytes()
    };
    let mut tlv_tbe = tlv::TlvBuffer::new();
    tlv_tbe.write_anon_struct()?;
    tlv_tbe.write_octetstring(1, ctrl_matter_cert)?;
    tlv_tbe.write_octetstring(3, &tbs)?;
    tlv_tbe.write_struct_end()?;

    let responder_public_key = p256::PublicKey::from_sec1_bytes(&ctx.responder_public)?;
    let shared = ctx.eph_key.diffie_hellman(&responder_public_key);
    let mut th = ctx.sigma1_payload.clone();
    th.extend_from_slice(&ctx.sigma2_payload);
    let transscript_hash = cryptoutil::sha256(&th);
    let mut s3_salt = fabric.signed_ipk()?;
    s3_salt.extend_from_slice(&transscript_hash);
    let s3k = cryptoutil::hkdf_sha256(
        &s3_salt,
        shared.raw_secret_bytes().as_slice(),
        "Sigma3".as_bytes(),
        16,
    )?;

    let aes_key = aes::cipher::crypto_common::Key::<Aes128Ccm>::from_slice(&s3k);
    let cipher = Aes128Ccm::new(aes_key);
    let encrypted = match cipher.encrypt(
        "NCASE_Sigma3N".as_bytes().into(),
        ccm::aead::Payload {
            msg: &tlv_tbe.data,
            aad: &[],
        },
    ) {
        Ok(e) => e,
        Err(e) => return Err(anyhow::anyhow!(format!("encrypt failed {:?}", e))),
    };
    let mut tlv_s3 = tlv::TlvBuffer::new();
    tlv_s3.write_anon_struct()?;
    tlv_s3.write_octetstring(1, &encrypted)?;
    tlv_s3.write_struct_end()?;
    ctx.sigma3_payload = tlv_s3.data;
    ctx.shared = Some(shared);

    Ok(())
}
