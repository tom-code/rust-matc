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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{cert_matter, cert_x509};

    #[test]
    fn test_sigma() -> Result<()> {
        const CA_NODE_ID: u64 = 5678;
        const FABRIC_ID: u64 = 1234;
        const NODE_ID: u64 = 1111;
        const CTRL_NODE_ID: u64 = 100;

        // Setup CA keypair and fabric
        let ca_secret_key = p256::SecretKey::random(&mut rand::thread_rng());
        let ca_public_key = ca_secret_key.public_key().to_sec1_bytes();
          let fabric = fabric::Fabric::new(FABRIC_ID, CA_NODE_ID, &ca_public_key);

        // Step 1: Generate sigma1 (initiator)
        let mut ctx = SigmaContext::new(NODE_ID);
        sigma1(&fabric, &mut ctx, &ca_public_key)?;
        let sigma1_tlv = tlv::decode_tlv(&ctx.sigma1_payload)?;
        let initiator_random = sigma1_tlv.get_octet_string(&[1]).unwrap();
        let session_id = sigma1_tlv.get_int(&[2]).unwrap();
        let dst_id = sigma1_tlv.get_octet_string(&[3]).unwrap();
        let initiator_eph_pubkey = sigma1_tlv.get_octet_string(&[4]).unwrap();

        // Verify sigma1 structure
        assert!(!initiator_random.is_empty(), "initiator random should not be empty");
        assert_eq!(session_id as u16, ctx.session_id, "session ID should match context");
        assert!(!dst_id.is_empty(), "dst_id should not be empty");
        assert_eq!(initiator_eph_pubkey.len(), 65, "ephemeral public key should be 65 bytes (uncompressed SEC1)");

        // Step 2: Simulate responder (device side)
        let node_ephemeral_secret = p256::ecdh::EphemeralSecret::random(&mut rand::thread_rng());
        let node_ephemeral_pubkey = node_ephemeral_secret.public_key().to_sec1_bytes();
        let responder_shared = node_ephemeral_secret.diffie_hellman(&p256::PublicKey::from_sec1_bytes(initiator_eph_pubkey)?);
        ctx.responder_public = node_ephemeral_pubkey.to_vec();
        ctx.responder_session = session_id as u16;

        // Step 3: Simulate sigma2 payload (needed for sigma3 transcript)
        let mut sigma2_tlv = tlv::TlvBuffer::new();
        sigma2_tlv.write_anon_struct()?;
        sigma2_tlv.write_uint16(2, ctx.responder_session)?;
        sigma2_tlv.write_octetstring(3, &node_ephemeral_pubkey)?;
        sigma2_tlv.write_struct_end()?;
        ctx.sigma2_payload = sigma2_tlv.data;

        // Step 4: Create controller keypair and certificate
        let ctrl_secret_key = p256::SecretKey::random(&mut rand::thread_rng());
        let ctrl_public_key = ctrl_secret_key.public_key().to_sec1_bytes();
        let ctrl_x509 = cert_x509::encode_x509(
            &ctrl_public_key,
            CTRL_NODE_ID,
            FABRIC_ID,
            CA_NODE_ID,
            &ca_secret_key,
            false,
        )?;
        let ctrl_matter_cert = cert_matter::convert_x509_bytes_to_matter(&ctrl_x509, &ca_public_key)?;
        let ctrl_private_der = cryptoutil::secret_key_to_rfc5915(&ctrl_secret_key)?;

        // Step 5: Generate sigma3 (initiator completes handshake)
        sigma3(&fabric, &mut ctx, &ctrl_private_der, &ctrl_matter_cert)?;

        // Verify sigma3 results
        assert!(!ctx.sigma3_payload.is_empty(), "sigma3 payload should not be empty");
        assert!(ctx.shared.is_some(), "shared secret should be established");

        let sigma3_tlv = tlv::decode_tlv(&ctx.sigma3_payload)?;
        let encrypted_blob = sigma3_tlv.get_octet_string(&[1]).unwrap();
        assert!(!encrypted_blob.is_empty(), "encrypted blob should not be empty");

        // Step 6: Derive session keys (initiator side)
        let mut transcript = ctx.sigma1_payload.clone();
        transcript.extend_from_slice(&ctx.sigma2_payload);
        transcript.extend_from_slice(&ctx.sigma3_payload);
        let transcript_hash = cryptoutil::sha256(&transcript);
        let mut salt = fabric.signed_ipk()?;
        salt.extend_from_slice(&transcript_hash);
        let initiator_shared = ctx.shared.as_ref().unwrap();
        let initiator_keypack = cryptoutil::hkdf_sha256(
            &salt,
            initiator_shared.raw_secret_bytes().as_slice(),
            "SessionKeys".as_bytes(),
            48,
        )?;

        // Step 7: Derive session keys (responder side - verify agreement)
        let responder_keypack = cryptoutil::hkdf_sha256(
            &salt,
            responder_shared.raw_secret_bytes().as_slice(),
            "SessionKeys".as_bytes(),
            48,
        )?;

        // Step 8: Verify both sides derived identical session keys
        assert_eq!(
            initiator_keypack, responder_keypack,
            "initiator and responder should derive identical session keys"
        );

        let i2r_key = &initiator_keypack[0..16];
        let r2i_key = &initiator_keypack[16..32];
        let attestation_challenge = &initiator_keypack[32..48];
        assert_eq!(i2r_key.len(), 16, "i2r key should be 16 bytes");
        assert_eq!(r2i_key.len(), 16, "r2i key should be 16 bytes");
        assert_eq!(attestation_challenge.len(), 16, "attestation challenge should be 16 bytes");

        // Step 9: Decrypt and verify sigma3 TBE from responder's perspective
        let mut th = ctx.sigma1_payload.clone();
        th.extend_from_slice(&ctx.sigma2_payload);
        let transcript_hash_s3 = cryptoutil::sha256(&th);
        let mut s3_salt = fabric.signed_ipk()?;
        s3_salt.extend_from_slice(&transcript_hash_s3);
        let s3k = cryptoutil::hkdf_sha256(
            &s3_salt,
            responder_shared.raw_secret_bytes().as_slice(),
            "Sigma3".as_bytes(),
            16,
        )?;

        let aes_key = aes::cipher::crypto_common::Key::<Aes128Ccm>::from_slice(&s3k);
        let cipher = Aes128Ccm::new(aes_key);
        let decrypted = cipher
            .decrypt(
                "NCASE_Sigma3N".as_bytes().into(),
                ccm::aead::Payload {
                    msg: encrypted_blob,
                    aad: &[],
                },
            )
            .expect("decryption should succeed");

        // Step 10: Verify sigma3 TBE contents
        let tbe_tlv = tlv::decode_tlv(&decrypted)?;
        let tbe_cert = tbe_tlv.get_octet_string(&[1]).unwrap();
        let tbe_signature = tbe_tlv.get_octet_string(&[3]).unwrap();

        assert_eq!(tbe_cert, ctrl_matter_cert, "TBE certificate should match controller certificate");
        assert_eq!(tbe_signature.len(), 64, "signature should be 64 bytes");

        Ok(())
    }
}