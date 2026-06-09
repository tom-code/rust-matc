//! Handling of x509 certificate compatible with matter

use byteorder::WriteBytesExt;
use std::time::{Duration, SystemTime};

use crate::tlv;
use crate::util::asn1;
use crate::util::cryptoutil;
use anyhow::{Context, Result};

fn add_ext(encoder: &mut asn1::Encoder, oid: &str, critical: bool, value: &[u8]) -> Result<()> {
    encoder.start_seq(0x30)?;
    encoder.write_oid(oid)?;
    if critical {
        encoder.write_bool(critical)?;
    }
    encoder.write_octet_string(value)?;
    encoder.end_seq();
    Ok(())
}

fn encode_nodeid(id: u64) -> String {
    format!("{:0>16X}", id)
}

fn systemtime_to_x509_time(st: std::time::SystemTime) -> Result<String> {
    let der_datetime = x509_cert::der::asn1::UtcTime::from_system_time(st)?;
    let mut v = Vec::new();
    x509_cert::der::EncodeValue::encode_value(&der_datetime, &mut v)?;
    Ok(std::str::from_utf8(&v)?.to_owned())
}

const OID_MATTER_DN_NODE: &str = "1.3.6.1.4.1.37244.1.1";
const OID_MATTER_DN_CA: &str = "1.3.6.1.4.1.37244.1.4";
const OID_MATTER_DN_FABRIC: &str = "1.3.6.1.4.1.37244.1.5";

const OID_SIG_ECDSA_WITH_SHA256: &str = "1.2.840.10045.4.3.2";

pub(crate) const OID_CE_SUBJECT_KEY_IDENTIFIER: &str = "2.5.29.14";
pub(crate) const OID_CE_KEY_USAGE: &str = "2.5.29.15";
pub(crate) const OID_CE_BASIC_CONSTRAINTS: &str = "2.5.29.19";
pub(crate) const OID_CE_EXT_KEU_USAGE: &str = "2.5.29.37";
pub(crate) const OID_CE_AUTHORITY_KEY_IDENTIFIER: &str = "2.5.29.35";

fn add_rdn(encoder: &mut asn1::Encoder, oid: &str, id: u64) -> Result<()> {
    encoder.start_seq(0x31)?; //rdn
    encoder.start_seq(0x30)?; //atv
    encoder.write_oid(oid)?;
    encoder.write_string(&encode_nodeid(id))?;
    encoder.end_seq();
    encoder.end_seq();
    Ok(())
}

fn epoch2000_to_x509_time(secs: u32) -> Result<String> {
    let st = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(946684800 + secs as u64))
        .context("certificate time out of range")?;
    systemtime_to_x509_time(st)
}

/// Reconstruct the X.509 TBSCertificate DER from a certificate in Matter TLV format.
/// Matter certificate signatures are computed over the X.509 TBS, so this is needed to
/// verify a Matter certificate against its issuer's public key.
/// Only certificates produced by [encode_x509] (this library's own CA) round-trip exactly;
/// certificates issued by other stacks may use encodings this reconstruction does not cover,
/// in which case signature verification will fail.
pub(crate) fn matter_cert_to_x509_tbs(matter_cert: &[u8]) -> Result<Vec<u8>> {
    let cert = tlv::decode_tlv(matter_cert)?;
    let serial = cert
        .get_octet_string(&[1])
        .context("matter cert: serial missing")?;
    let issuer_ca_id = cert
        .get_int(&[3, 20])
        .context("matter cert: issuer ca id missing")?;
    let not_before = cert.get_int(&[4]).context("matter cert: not_before missing")? as u32;
    let not_after = cert.get_int(&[5]).context("matter cert: not_after missing")? as u32;
    let public_key = cert
        .get_octet_string(&[9])
        .context("matter cert: public key missing")?;
    let is_ca = cert.get_bool(&[10, 1, 1]).unwrap_or(false);
    let subject_key_id = cert
        .get_octet_string(&[10, 4])
        .context("matter cert: subject key id missing")?;
    let authority_key_id = cert
        .get_octet_string(&[10, 5])
        .context("matter cert: authority key id missing")?;

    let mut encoder = asn1::Encoder::new();
    encoder.start_seq(0x30)?;

    encoder.start_seq(0xa0)?;
    encoder.write_int(2)?; // version
    encoder.end_seq();

    encoder.write_octet_string_with_tag(0x2, serial)?; // serial INTEGER content bytes

    encoder.start_seq(0x30)?; //signature algorithm
    encoder.write_oid(OID_SIG_ECDSA_WITH_SHA256)?;
    encoder.end_seq();

    encoder.start_seq(0x30)?; //issuer
    add_rdn(&mut encoder, OID_MATTER_DN_CA, issuer_ca_id)?;
    encoder.end_seq();

    encoder.start_seq(0x30)?; //validity
    encoder.write_string_with_tag(0x17, &epoch2000_to_x509_time(not_before)?)?;
    encoder.write_string_with_tag(0x17, &epoch2000_to_x509_time(not_after)?)?;
    encoder.end_seq();

    encoder.start_seq(0x30)?; //subject
    if is_ca {
        let subject_ca_id = cert
            .get_int(&[6, 20])
            .context("matter cert: subject ca id missing")?;
        add_rdn(&mut encoder, OID_MATTER_DN_CA, subject_ca_id)?;
    } else {
        let node_id = cert
            .get_int(&[6, 17])
            .context("matter cert: subject node id missing")?;
        let fabric_id = cert
            .get_int(&[6, 21])
            .context("matter cert: subject fabric id missing")?;
        add_rdn(&mut encoder, OID_MATTER_DN_NODE, node_id)?;
        add_rdn(&mut encoder, OID_MATTER_DN_FABRIC, fabric_id)?;
    }
    encoder.end_seq();

    encoder.start_seq(0x30)?; //subject key info
    encoder.start_seq(0x30)?; //algorithm
    encoder.write_oid("1.2.840.10045.2.1")?;
    encoder.write_oid("1.2.840.10045.3.1.7")?;
    encoder.end_seq();
    let mut pk2 = vec![0u8];
    pk2.extend_from_slice(public_key);
    encoder.write_octet_string_with_tag(0x3, &pk2)?;
    encoder.end_seq();

    let subjectkeyidasn = {
        let mut encoder = asn1::Encoder::new();
        encoder.write_octet_string(subject_key_id)?;
        encoder.encode()
    };

    let authoritykey_sha1_asn = {
        let mut encoder = asn1::Encoder::new();
        encoder.start_seq(0x30)?;
        encoder.write_octet_string_with_tag(0x80, authority_key_id)?;
        encoder.encode()
    };

    encoder.start_seq(0xa3)?;
    encoder.start_seq(0x30)?;
    if is_ca {
        add_ext(
            &mut encoder,
            OID_CE_BASIC_CONSTRAINTS,
            true,
            &[0x30, 0x03, 0x01, 0x01, 0xFF],
        )?;
        add_ext(
            &mut encoder,
            OID_CE_KEY_USAGE,
            true,
            &[0x03, 0x02, 0x01, 0x06],
        )?;
    } else {
        add_ext(&mut encoder, OID_CE_BASIC_CONSTRAINTS, true, &[0x30, 0x00])?;
        add_ext(
            &mut encoder,
            OID_CE_KEY_USAGE,
            true,
            &[0x03, 0x02, 0x07, 0x80],
        )?;
        let mut ext_ku_encoder = asn1::Encoder::new();
        ext_ku_encoder.start_seq(0x30)?;
        ext_ku_encoder.write_oid("1.3.6.1.5.5.7.3.2")?; // client-auth
        ext_ku_encoder.write_oid("1.3.6.1.5.5.7.3.1")?; // server-auth
        let ext_ku_bytes = ext_ku_encoder.encode();
        add_ext(&mut encoder, OID_CE_EXT_KEU_USAGE, true, &ext_ku_bytes)?;
    }
    add_ext(
        &mut encoder,
        OID_CE_SUBJECT_KEY_IDENTIFIER,
        false,
        &subjectkeyidasn,
    )?;
    add_ext(
        &mut encoder,
        OID_CE_AUTHORITY_KEY_IDENTIFIER,
        false,
        &authoritykey_sha1_asn,
    )?;
    encoder.end_seq();
    encoder.end_seq();
    encoder.end_seq();

    Ok(encoder.encode())
}

/// Create matter compatible certificate in x509 format.
pub fn encode_x509(
    node_public_key: &[u8],
    node_id: u64,
    fabric_id: u64,
    ca_id: u64,
    ca_private: &p256::SecretKey,
    ca: bool,
) -> Result<Vec<u8>> {
    let mut encoder = asn1::Encoder::new();
    encoder.start_seq(0x30)?;
    encoder.start_seq(0x30)?;

    encoder.start_seq(0xa0)?;
    encoder.write_int(2)?; // version
    encoder.end_seq();

    encoder.write_int(10001)?; // serial

    encoder.start_seq(0x30)?; //signature algorithm
    encoder.write_oid(OID_SIG_ECDSA_WITH_SHA256)?;
    encoder.end_seq();

    encoder.start_seq(0x30)?; //issuer
    add_rdn(&mut encoder, OID_MATTER_DN_CA, ca_id)?;
    encoder.end_seq();

    encoder.start_seq(0x30)?; //validity

    let now = SystemTime::now();
    encoder.write_string_with_tag(0x17, &systemtime_to_x509_time(now)?)?;
    let not_after = now
        .checked_add(Duration::from_secs(60 * 60 * 24 * 100))
        .context("time continuity error")?;
    encoder.write_string_with_tag(0x17, &systemtime_to_x509_time(not_after)?)?;
    encoder.end_seq();

    if ca {
        encoder.start_seq(0x30)?; //subject
        add_rdn(&mut encoder, OID_MATTER_DN_CA, node_id)?;
        encoder.end_seq();
    } else {
        encoder.start_seq(0x30)?; //subject
        add_rdn(&mut encoder, OID_MATTER_DN_NODE, node_id)?;
        add_rdn(&mut encoder, OID_MATTER_DN_FABRIC, fabric_id)?;
        encoder.end_seq();
    }

    encoder.start_seq(0x30)?; //subject key info
    encoder.start_seq(0x30)?; //algorithm
    encoder.write_oid("1.2.840.10045.2.1")?;
    encoder.write_oid("1.2.840.10045.3.1.7")?;
    encoder.end_seq();

    let mut pk2 = Vec::new();
    pk2.write_u8(0)?;

    pk2.extend_from_slice(node_public_key);
    encoder.write_octet_string_with_tag(0x3, &pk2)?;
    encoder.end_seq();

    let subjectkeyidasn = {
        let mut encoder = asn1::Encoder::new();
        encoder.write_octet_string(&cryptoutil::sha1_enc(node_public_key))?;
        encoder.encode()
    };

    let authoritykey_sha1_asn = {
        let mut encoder = asn1::Encoder::new();
        encoder.start_seq(0x30)?;
        let pubkey = ca_private.public_key().to_sec1_bytes();
        encoder.write_octet_string_with_tag(0x80, &cryptoutil::sha1_enc(&pubkey))?;
        encoder.encode()
    };

    encoder.start_seq(0xa3)?;
    encoder.start_seq(0x30)?;
    // basic constraints
    if ca {
        add_ext(
            &mut encoder,
            OID_CE_BASIC_CONSTRAINTS,
            true,
            &[0x30, 0x03, 0x01, 0x01, 0xFF],
        )?
    } else {
        add_ext(&mut encoder, OID_CE_BASIC_CONSTRAINTS, true, &[0x30, 0x00])?
    }
    // key usage
    if ca {
        add_ext(
            &mut encoder,
            OID_CE_KEY_USAGE,
            true,
            &[0x03, 0x02, 0x01, 0x06],
        )?;
    } else {
        add_ext(
            &mut encoder,
            OID_CE_KEY_USAGE,
            true,
            &[0x03, 0x02, 0x07, 0x80],
        )?;
    }
    //ext key usage
    if !ca {
        let mut ext_ku_encoder = asn1::Encoder::new();
        ext_ku_encoder.start_seq(0x30)?;
        ext_ku_encoder.write_oid("1.3.6.1.5.5.7.3.2")?; // client-auth
        ext_ku_encoder.write_oid("1.3.6.1.5.5.7.3.1")?; // server-auth
        let ext_ku_bytes = ext_ku_encoder.encode();
        add_ext(&mut encoder, OID_CE_EXT_KEU_USAGE, true, &ext_ku_bytes)?;
    }
    //subject key id
    add_ext(
        &mut encoder,
        OID_CE_SUBJECT_KEY_IDENTIFIER,
        false,
        &subjectkeyidasn,
    )?;

    //authority key id
    add_ext(
        &mut encoder,
        OID_CE_AUTHORITY_KEY_IDENTIFIER,
        false,
        &authoritykey_sha1_asn,
    )?;

    encoder.end_seq();
    encoder.end_seq();
    encoder.end_seq();

    let to_sign = encoder.clone();
    let to_sign_bytes = &to_sign.encode()[4..];
    let key = ecdsa::SigningKey::from(ca_private);
    let signed = key.sign_recoverable(to_sign_bytes)?.0;

    encoder.start_seq(0x30)?; //alg
    encoder.write_oid(OID_SIG_ECDSA_WITH_SHA256)?;
    encoder.end_seq();
    let mut signed_b = vec![0];
    signed_b.extend_from_slice(signed.to_der().as_bytes());

    encoder.write_octet_string_with_tag(0x3, &signed_b)?;

    let res = encoder.encode();

    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn der_element(der: &[u8]) -> &[u8] {
        match der[1] {
            l if l < 0x80 => &der[..2 + l as usize],
            0x81 => &der[..3 + der[2] as usize],
            0x82 => &der[..4 + ((der[2] as usize) << 8) + der[3] as usize],
            _ => panic!("unsupported DER length"),
        }
    }

    #[test]
    fn test_matter_cert_to_x509_tbs_roundtrip() -> Result<()> {
        let ca_secret = p256::SecretKey::random(&mut rand::thread_rng());
        let ca_public = ca_secret.public_key().to_sec1_bytes();
        for is_ca in [false, true] {
            let node_secret = p256::SecretKey::random(&mut rand::thread_rng());
            let node_public = node_secret.public_key().to_sec1_bytes();
            let x509 = encode_x509(&node_public, 1111, 1234, 5678, &ca_secret, is_ca)?;
            let matter = crate::cert_matter::convert_x509_bytes_to_matter(&x509, &ca_public)?;
            let tbs = matter_cert_to_x509_tbs(&matter)?;

            let header = match x509[1] {
                l if l < 0x80 => 2,
                0x81 => 3,
                0x82 => 4,
                _ => panic!("unsupported DER length"),
            };
            let expected_tbs = der_element(&x509[header..]);
            assert_eq!(tbs, expected_tbs, "reconstructed TBS must match original (is_ca={})", is_ca);

            let cert_tlv = tlv::decode_tlv(&matter)?;
            let sig = cert_tlv.get_octet_string(&[11]).unwrap();
            let verifying_key =
                ecdsa::VerifyingKey::from(p256::PublicKey::from_sec1_bytes(&ca_public)?);
            let sig = ecdsa::Signature::<p256::NistP256>::from_slice(sig)?;
            ecdsa::signature::Verifier::verify(&verifying_key, &tbs, &sig)?;
        }
        Ok(())
    }
}
