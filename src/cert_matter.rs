//! Handling of certificates in Matter format

use anyhow::{Context, Result};
use p256::NistP256;
use x509_cert::{
    certificate::CertificateInner,
    der::{Decode, DecodePem},
};

use crate::{
    tlv::{self, TlvBuffer},
    util::cryptoutil,
};

fn decode_dn_value(dn: &x509_cert::der::Any) -> Result<u64> {
    let valstr = dn.decode_as::<String>()?;
    Ok(u64::from_str_radix(&valstr, 16)?)
}

fn dn_to_matter(dn: &x509_cert::name::RdnSequence, tlv: &mut TlvBuffer) -> Result<()> {
    for extra in &dn.0 {
        for e2 in extra.0.as_slice() {
            if e2.oid == const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.37244.1.1") {
                tlv.write_uint64(17, decode_dn_value(&e2.value)?)?;
            }
            if e2.oid == const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.37244.1.4") {
                tlv.write_uint64(20, decode_dn_value(&e2.value)?)?;
            }
            if e2.oid == const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.37244.1.5") {
                tlv.write_uint64(21, decode_dn_value(&e2.value)?)?;
            }
        }
    }
    Ok(())
}

fn extract_extension(cert: &x509_cert::TbsCertificate, oid: &str) -> Result<Vec<u8>> {
    let extensions = cert
        .extensions
        .as_ref()
        .context("can't get cert extensions")?;
    for extension in extensions {
        if extension.extn_id == const_oid::ObjectIdentifier::new_unwrap(oid) {
            let v = extension.extn_value.as_bytes().to_vec();
            return Ok(v);
        }
    }
    Err(anyhow::anyhow!(format!("can't find extension {:?}", oid)))
}

pub fn get_subject_node_id_from_x509(fname: &str) -> Result<u64> {
    let cert_file = std::fs::read_to_string(fname)?;
    let cert = x509_cert::Certificate::from_pem(cert_file)?;
    for extra in cert.tbs_certificate.subject.0 {
        for e2 in extra.0.as_slice() {
            if e2.oid == const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.37244.1.1") {
                return decode_dn_value(&e2.value);
            }
        }
    }
    Err(anyhow::anyhow!("matter subject/node not found in x509"))
}

/// Convert certificate in PEM file to matter format
/// PEM file must contain x509 certificate compatible with matter
pub fn convert_x509_to_matter(fname: &str, ca_pubkey: &[u8]) -> Result<Vec<u8>> {
    let x509_raw = cryptoutil::read_data_from_pem(fname)?;
    convert_x509_bytes_to_matter(&x509_raw, ca_pubkey)
}

/// Convert certificate from X509/DER array of bytes to matter format
/// x509 certificate must be compatible with matter
pub fn convert_x509_bytes_to_matter(bytes: &[u8], ca_pubkey: &[u8]) -> Result<Vec<u8>> {
    let x509 = x509_cert::Certificate::from_der(bytes)?;
    convert_x509_to_matter_int(&x509, ca_pubkey)
}

fn convert_x509_to_matter_int(cert: &CertificateInner, ca_pubkey: &[u8]) -> Result<Vec<u8>> {
    let mut enc = tlv::TlvBuffer::new();
    enc.write_anon_struct()?;
    enc.write_octetstring(1, cert.tbs_certificate.serial_number.as_bytes())?;
    enc.write_uint8(2, 1)?; //signature algorithm

    enc.write_list(3)?; // issuer
    dn_to_matter(&cert.tbs_certificate.issuer, &mut enc)?;
    enc.write_struct_end()?;

    let not_before = cert.tbs_certificate.validity.not_before;
    enc.write_uint32(
        4,
        (not_before.to_unix_duration().as_secs() - 946684800) as u32,
    )?;
    let not_after = cert.tbs_certificate.validity.not_after;
    enc.write_uint32(
        5,
        (not_after.to_unix_duration().as_secs() - 946684800) as u32,
    )?;

    enc.write_list(6)?; // subject
    dn_to_matter(&cert.tbs_certificate.subject, &mut enc)?;
    enc.write_struct_end()?;

    enc.write_uint8(7, 1)?;
    enc.write_uint8(8, 1)?;

    let subject_public_key = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .context("can't extract subject public key")?;

    enc.write_octetstring(9, subject_public_key)?;

    enc.write_list(10)?;
    enc.write_struct(1)?;
    let is_ca = {
        let basicc = extract_extension(
            &cert.tbs_certificate,
            crate::cert_x509::OID_CE_BASIC_CONSTRAINTS,
        );
        if let Ok(v) = basicc {
            v[v.len() - 1] == 0xff
        } else {
            false
        }
    };
    enc.write_bool(1, is_ca)?;
    enc.write_struct_end()?;
    let kus = extract_extension(&cert.tbs_certificate, crate::cert_x509::OID_CE_KEY_USAGE)?;
    let kus = x509_cert::ext::pkix::KeyUsage::from_der(&kus)?;

    enc.write_uint8(2, kus.0.bits() as u8)?;
    ///////// ext key usage
    let extu = extract_extension(
        &cert.tbs_certificate,
        crate::cert_x509::OID_CE_EXT_KEU_USAGE,
    );
    if extu.is_ok() {
        enc.write_array(0x3)?;
        let extu = x509_cert::ext::pkix::ExtendedKeyUsage::from_der(&extu?)?;
        for u in extu.0 {
            match u.to_string().as_str() {
                "1.3.6.1.5.5.7.3.1" => {
                    enc.write_uint8_notag(1)?;
                } // server-auth
                "1.3.6.1.5.5.7.3.2" => {
                    enc.write_uint8_notag(2)?;
                } // client-auth
                _ => {
                    return Err(anyhow::anyhow!(
                        "unsupported oid in extendedKeyUsage {:?}",
                        u.to_string()
                    ))
                }
            };
        }
        enc.write_struct_end()?;
    }

    // do-sha1
    let cakey_sha1 = cryptoutil::sha1_enc(ca_pubkey);

    enc.write_octetstring(
        4,
        &extract_extension(
            &cert.tbs_certificate,
            crate::cert_x509::OID_CE_SUBJECT_KEY_IDENTIFIER,
        )?[2..],
    )?;
    enc.write_octetstring(5, &cakey_sha1)?;
    enc.write_struct_end()?;

    let sig = cert
        .signature
        .as_bytes()
        .context("can't get signature from x509")?;

    let sig = ecdsa::Signature::<NistP256>::from_der(sig)?;

    enc.write_octetstring(11, sig.to_bytes().as_slice())?;

    enc.write_struct_end()?;
    Ok(enc.data)
}
