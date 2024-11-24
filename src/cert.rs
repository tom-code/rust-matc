use std::time::{Duration, SystemTime};
use byteorder::WriteBytesExt;

use crate::asn1;
use anyhow::{Result, Context};


fn add_ext(encoder: &mut asn1::Encoder, oid: &str, critical: bool, value: &[u8]) -> Result<()>{
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
    format!("{:0>16x}", id)
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




pub fn encode_x509(node_public_key: &[u8], node_id: u64, fabric_id: u64, ca_id: u64, ca_private: &p256::SecretKey, ca: bool) -> Result<Vec<u8>> {
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
    encoder.start_seq(0x31)?; //rdn
    encoder.start_seq(0x30)?; //atv
    encoder.write_oid(OID_MATTER_DN_CA)?;
    encoder.write_string(&encode_nodeid(ca_id))?;
    encoder.end_seq();
    encoder.end_seq();
    encoder.end_seq();

    encoder.start_seq(0x30)?; //validity

    let now = SystemTime::now();
    encoder.write_string_with_tag(0x17, &systemtime_to_x509_time(now)?)?;
    let not_after = now.checked_add(Duration::from_secs(60*60*24*100)).context("time continuity error")?;
    encoder.write_string_with_tag(0x17, &systemtime_to_x509_time(not_after)?)?;
    encoder.end_seq();

    if ca {
        encoder.start_seq(0x30)?; //subject
        encoder.start_seq(0x31)?; //rdn
        encoder.start_seq(0x30)?; //atv
        encoder.write_oid(OID_MATTER_DN_CA)?;
        encoder.write_string(&encode_nodeid(node_id))?;
        encoder.end_seq();
        encoder.end_seq();
        encoder.end_seq();
    } else {
        encoder.start_seq(0x30)?; //subject
        encoder.start_seq(0x31)?; //rdn
        encoder.start_seq(0x30)?; //atv
        encoder.write_oid(OID_MATTER_DN_NODE)?;
        encoder.write_string(&encode_nodeid(node_id))?;
        encoder.end_seq();
        encoder.end_seq();

        encoder.start_seq(0x31)?; //rdn
        encoder.start_seq(0x30)?; //atv
        encoder.write_oid(OID_MATTER_DN_FABRIC)?;
        encoder.write_string(&encode_nodeid(fabric_id))?;
        encoder.end_seq();
        encoder.end_seq();
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

    let pubkey_sha1 = crate::cryptoutil::sha1_enc(node_public_key);
    let mut subjectkeyidasn = vec![0x04, 0x14];
    subjectkeyidasn.extend_from_slice(&pubkey_sha1);

    let pubkey = ca_private.public_key().to_sec1_bytes();
    let authoritykey_sha1 = crate::cryptoutil::sha1_enc(&pubkey);
    let mut authoritykey_sha1_asn = vec![0x30, 0x16, 0x80, 0x14];
    authoritykey_sha1_asn.extend_from_slice(&authoritykey_sha1);

    encoder.start_seq(0xa3)?;
    encoder.start_seq(0x30)?;
    // basic constraints
    add_ext(&mut encoder, "2.5.29.19", true, &[0x30, 0x03, 0x01, 0x01, 0xFF])?;
    // key usage
    if ca {
        add_ext(&mut encoder, "2.5.29.15", true, &[0x03, 0x02, 0x01, 0x06])?;
    } else {
        add_ext(&mut encoder, "2.5.29.15", true, &[0x03, 0x02, 0x07, 0x80])?;
    }
    //ext key usage
    if !ca {
        add_ext(&mut encoder, "2.5.29.37", true, &[0x30, 0x14, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01])?;
    }
    //subject key id
    add_ext(&mut encoder, "2.5.29.14", false, &subjectkeyidasn)?;
    //authority key id
    add_ext(&mut encoder, "2.5.29.35", false, &authoritykey_sha1_asn)?;

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