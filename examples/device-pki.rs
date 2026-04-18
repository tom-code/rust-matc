use anyhow::Result;
use clap::{Parser, Subcommand};
use matc::util::asn1;
use matc::util::cryptoutil::{
    read_data_from_pem, read_private_key_from_pem, secret_key_to_rfc5915, sha1_enc, write_pem,
};
use std::time::{Duration, SystemTime};
use x509_cert::der::{Decode, Encode};

const OID_SIG_ECDSA_WITH_SHA256: &str = "1.2.840.10045.4.3.2";
const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const OID_P256: &str = "1.2.840.10045.3.1.7";
const OID_CN: &str = "2.5.4.3";
const OID_MATTER_VENDOR_ID: &str = "1.3.6.1.4.1.37244.2.1";
const OID_MATTER_PRODUCT_ID: &str = "1.3.6.1.4.1.37244.2.2";
const OID_BASIC_CONSTRAINTS: &str = "2.5.29.19";
const OID_KEY_USAGE: &str = "2.5.29.15";
const OID_SKID: &str = "2.5.29.14";
const OID_AKID: &str = "2.5.29.35";

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
#[allow(clippy::enum_variant_names)]
enum Commands {
    /// Create a self-signed CA certificate (PAA-style)
    CreateCa {
        #[arg(long, default_value = "Matter PAA")]
        cn: String,
        #[arg(long)]
        vendor_id: u16,
        #[arg(long, default_value = "paa-cert.pem")]
        out_cert: String,
        #[arg(long, default_value = "paa-key.pem")]
        out_key: String,
        #[arg(long, default_value = "30")]
        validity_years: u32,
    },
    /// Create an intermediate CA certificate (PAI-style) signed by the PAA
    CreatePai {
        #[arg(long, default_value = "Matter PAI")]
        cn: String,
        #[arg(long)]
        vendor_id: u16,
        #[arg(long, default_value = "paa-cert.pem")]
        ca_cert: String,
        #[arg(long, default_value = "paa-key.pem")]
        ca_key: String,
        #[arg(long, default_value = "pai-cert.pem")]
        out_cert: String,
        #[arg(long, default_value = "pai-key.pem")]
        out_key: String,
        #[arg(long, default_value = "20")]
        validity_years: u32,
    },
    /// Create a leaf certificate signed by the CA (DAC-style)
    CreateDac {
        #[arg(long, default_value = "Matter Device")]
        cn: String,
        #[arg(long)]
        vendor_id: u16,
        #[arg(long)]
        product_id: u16,
        #[arg(long, default_value = "paa-cert.pem")]
        ca_cert: String,
        #[arg(long, default_value = "paa-key.pem")]
        ca_key: String,
        #[arg(long, default_value = "dac-cert.pem")]
        out_cert: String,
        #[arg(long, default_value = "dac-key.pem")]
        out_key: String,
        #[arg(long, default_value = "10")]
        validity_years: u32,
    },
}

/// Append a DER INTEGER tag+length+value for a u64 serial number.
fn write_serial(enc: &mut asn1::Encoder, serial: u64) {
    let mut bytes = serial.to_be_bytes().to_vec();
    // Strip leading zeros (but keep at least one byte)
    while bytes.len() > 1 && bytes[0] == 0 {
        bytes.remove(0);
    }
    // Ensure positive: prepend 0x00 if high bit is set
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0x00);
    }
    let mut raw = vec![0x02u8]; // INTEGER tag
    let len = bytes.len();
    if len < 0x80 {
        raw.push(len as u8);
    } else {
        raw.push(0x81);
        raw.push(len as u8);
    }
    raw.extend_from_slice(&bytes);
    enc.write_raw(&raw);
}

/// Write a UTCTime (years ≤ 2049) or GeneralizedTime (years ≥ 2050) into the encoder.
fn write_x509_time(enc: &mut asn1::Encoder, st: SystemTime) -> Result<()> {
    if let Ok(utc) = x509_cert::der::asn1::UtcTime::from_system_time(st) {
        let mut v = Vec::new();
        x509_cert::der::EncodeValue::encode_value(&utc, &mut v)?;
        enc.write_string_with_tag(0x17, std::str::from_utf8(&v)?)?;
    } else {
        let gt = x509_cert::der::asn1::GeneralizedTime::from_system_time(st)?;
        let mut v = Vec::new();
        x509_cert::der::EncodeValue::encode_value(&gt, &mut v)?;
        enc.write_string_with_tag(0x18, std::str::from_utf8(&v)?)?;
    }
    Ok(())
}

/// Build a complete DER-encoded Name (SEQUENCE of RDNs).
fn build_dn(cn: &str, vendor_id: u16, product_id: Option<u16>) -> Result<Vec<u8>> {
    let mut enc = asn1::Encoder::new();
    enc.start_seq(0x30)?; // Name SEQUENCE

    // CN RDN
    enc.start_seq(0x31)?; // SET
    enc.start_seq(0x30)?; // AttributeTypeAndValue
    enc.write_oid(OID_CN)?;
    enc.write_string(cn)?;
    enc.end_seq();
    enc.end_seq();

    // VendorID RDN
    enc.start_seq(0x31)?;
    enc.start_seq(0x30)?;
    enc.write_oid(OID_MATTER_VENDOR_ID)?;
    enc.write_string(&format!("{:04X}", vendor_id))?;
    enc.end_seq();
    enc.end_seq();

    // ProductID RDN (leaf certs only)
    if let Some(pid) = product_id {
        enc.start_seq(0x31)?;
        enc.start_seq(0x30)?;
        enc.write_oid(OID_MATTER_PRODUCT_ID)?;
        enc.write_string(&format!("{:04X}", pid))?;
        enc.end_seq();
        enc.end_seq();
    }

    enc.end_seq(); // Name SEQUENCE
    Ok(enc.encode())
}

/// Encode a single X.509v3 extension into the encoder.
fn add_ext(enc: &mut asn1::Encoder, oid: &str, critical: bool, value: &[u8]) -> Result<()> {
    enc.start_seq(0x30)?;
    enc.write_oid(oid)?;
    if critical {
        enc.write_bool(true)?;
    }
    enc.write_octet_string(value)?;
    enc.end_seq();
    Ok(())
}

/// Build a complete TBSCertificate DER SEQUENCE.
#[allow(clippy::too_many_arguments)]
fn encode_tbs(
    subject_pubkey: &[u8],
    subject_dn: &[u8],
    issuer_dn: &[u8],
    ca_pubkey: &[u8],
    serial: u64,
    not_before: SystemTime,
    not_after: SystemTime,
    ca_pathlen: Option<u8>,
) -> Result<Vec<u8>> {
    let mut enc = asn1::Encoder::new();
    enc.start_seq(0x30)?; // TBSCertificate

    // Version v3
    enc.start_seq(0xa0)?;
    enc.write_int(2)?;
    enc.end_seq();

    // Serial number
    write_serial(&mut enc, serial);

    // Signature algorithm
    enc.start_seq(0x30)?;
    enc.write_oid(OID_SIG_ECDSA_WITH_SHA256)?;
    enc.end_seq();

    // Issuer DN (pre-encoded)
    enc.write_raw(issuer_dn);

    // Validity
    enc.start_seq(0x30)?;
    write_x509_time(&mut enc, not_before)?;
    write_x509_time(&mut enc, not_after)?;
    enc.end_seq();

    // Subject DN (pre-encoded)
    enc.write_raw(subject_dn);

    // SubjectPublicKeyInfo
    enc.start_seq(0x30)?;
    enc.start_seq(0x30)?;
    enc.write_oid(OID_EC_PUBLIC_KEY)?;
    enc.write_oid(OID_P256)?;
    enc.end_seq();
    let mut pk_bs = vec![0x00u8]; // unused bits prefix for BIT STRING
    pk_bs.extend_from_slice(subject_pubkey);
    enc.write_octet_string_with_tag(0x03, &pk_bs)?;
    enc.end_seq();

    // Build SKID and AKID values
    let skid_val = {
        let mut e = asn1::Encoder::new();
        e.write_octet_string(&sha1_enc(subject_pubkey))?;
        e.encode()
    };
    let akid_val = {
        let mut e = asn1::Encoder::new();
        e.start_seq(0x30)?;
        e.write_octet_string_with_tag(0x80, &sha1_enc(ca_pubkey))?;
        e.encode()
    };

    // Extensions [3] EXPLICIT
    enc.start_seq(0xa3)?;
    enc.start_seq(0x30)?;

    if let Some(pathlen) = ca_pathlen {
        // BasicConstraints: CA:TRUE, pathlen:N
        let bc = [0x30, 0x06, 0x01, 0x01, 0xFF, 0x02, 0x01, pathlen];
        add_ext(&mut enc, OID_BASIC_CONSTRAINTS, true, &bc)?;
        // KeyUsage: Certificate Sign + CRL Sign
        add_ext(&mut enc, OID_KEY_USAGE, true, &[0x03, 0x02, 0x01, 0x06])?;
    } else {
        // BasicConstraints: CA:FALSE (empty SEQUENCE)
        add_ext(&mut enc, OID_BASIC_CONSTRAINTS, true, &[0x30, 0x00])?;
        // KeyUsage: Digital Signature
        add_ext(&mut enc, OID_KEY_USAGE, true, &[0x03, 0x02, 0x07, 0x80])?;
    }

    // SubjectKeyIdentifier
    add_ext(&mut enc, OID_SKID, false, &skid_val)?;
    // AuthorityKeyIdentifier
    add_ext(&mut enc, OID_AKID, false, &akid_val)?;

    enc.end_seq(); // extensions SEQUENCE
    enc.end_seq(); // [3] EXPLICIT

    enc.end_seq(); // TBSCertificate
    Ok(enc.encode())
}

/// Sign TBS bytes and assemble the complete DER Certificate.
fn encode_cert(tbs: &[u8], ca_private: &p256::SecretKey) -> Result<Vec<u8>> {
    let signing_key = ecdsa::SigningKey::from(ca_private);
    let (sig, _) = signing_key.sign_recoverable(tbs)?;
    let sig_der = sig.to_der();

    let mut enc = asn1::Encoder::new();
    enc.start_seq(0x30)?; // Certificate
    enc.write_raw(tbs);
    enc.start_seq(0x30)?;
    enc.write_oid(OID_SIG_ECDSA_WITH_SHA256)?;
    enc.end_seq();
    let mut sig_bs = vec![0x00u8]; // unused bits prefix
    sig_bs.extend_from_slice(sig_der.as_bytes());
    enc.write_octet_string_with_tag(0x03, &sig_bs)?;
    enc.end_seq(); // Certificate
    Ok(enc.encode())
}

fn create_ca(
    cn: &str,
    vendor_id: u16,
    out_cert: &str,
    out_key: &str,
    validity_years: u32,
) -> Result<()> {
    let key = p256::SecretKey::random(&mut rand::thread_rng());
    let pubkey = key.public_key().to_sec1_bytes().to_vec();

    let serial: u64 = rand::random();
    let now = SystemTime::now();
    let not_after = now + Duration::from_secs(validity_years as u64 * 365 * 24 * 3600);

    let dn = build_dn(cn, vendor_id, None)?;
    let tbs = encode_tbs(&pubkey, &dn, &dn, &pubkey, serial, now, not_after, Some(1))?;
    let cert_der = encode_cert(&tbs, &key)?;

    write_pem("CERTIFICATE", &cert_der, out_cert)?;
    let key_der = secret_key_to_rfc5915(&key)?;
    write_pem("EC PRIVATE KEY", &key_der, out_key)?;

    println!("Created CA cert: {out_cert}");
    println!("Created CA key:  {out_key}");
    Ok(())
}

fn create_pai(
    cn: &str,
    vendor_id: u16,
    ca_cert: &str,
    ca_key: &str,
    out_cert: &str,
    out_key: &str,
    validity_years: u32,
) -> Result<()> {
    let key = p256::SecretKey::random(&mut rand::thread_rng());
    let pubkey = key.public_key().to_sec1_bytes().to_vec();

    let ca_private = read_private_key_from_pem(ca_key)?;
    let ca_pubkey = ca_private.public_key().to_sec1_bytes().to_vec();

    let ca_cert_der = read_data_from_pem(ca_cert)?;
    let ca_x509 = x509_cert::Certificate::from_der(&ca_cert_der)?;
    let issuer_dn_bytes = ca_x509.tbs_certificate.subject.to_der()?;

    let serial: u64 = rand::random();
    let now = SystemTime::now();
    let not_after = now + Duration::from_secs(validity_years as u64 * 365 * 24 * 3600);

    let subject_dn = build_dn(cn, vendor_id, None)?;
    let tbs = encode_tbs(
        &pubkey,
        &subject_dn,
        &issuer_dn_bytes,
        &ca_pubkey,
        serial,
        now,
        not_after,
        Some(0),
    )?;
    let cert_der = encode_cert(&tbs, &ca_private)?;

    write_pem("CERTIFICATE", &cert_der, out_cert)?;
    let key_der = secret_key_to_rfc5915(&key)?;
    write_pem("EC PRIVATE KEY", &key_der, out_key)?;

    println!("Created PAI cert: {out_cert}");
    println!("Created PAI key:  {out_key}");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn create_dac(
    cn: &str,
    vendor_id: u16,
    product_id: u16,
    ca_cert: &str,
    ca_key: &str,
    out_cert: &str,
    out_key: &str,
    validity_years: u32,
) -> Result<()> {
    let key = p256::SecretKey::random(&mut rand::thread_rng());
    let pubkey = key.public_key().to_sec1_bytes().to_vec();

    let ca_private = read_private_key_from_pem(ca_key)?;
    let ca_pubkey = ca_private.public_key().to_sec1_bytes().to_vec();

    // Extract issuer DN bytes from the CA certificate
    let ca_cert_der = read_data_from_pem(ca_cert)?;
    let ca_x509 = x509_cert::Certificate::from_der(&ca_cert_der)?;
    let issuer_dn_bytes = ca_x509.tbs_certificate.subject.to_der()?;

    let serial: u64 = rand::random();
    let now = SystemTime::now();
    let not_after = now + Duration::from_secs(validity_years as u64 * 365 * 24 * 3600);

    let subject_dn = build_dn(cn, vendor_id, Some(product_id))?;
    let tbs = encode_tbs(
        &pubkey,
        &subject_dn,
        &issuer_dn_bytes,
        &ca_pubkey,
        serial,
        now,
        not_after,
        None,
    )?;
    let cert_der = encode_cert(&tbs, &ca_private)?;

    write_pem("CERTIFICATE", &cert_der, out_cert)?;
    let key_der = secret_key_to_rfc5915(&key)?;
    write_pem("EC PRIVATE KEY", &key_der, out_key)?;

    println!("Created DAC cert: {out_cert}");
    println!("Created DAC key:  {out_key}");
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::CreateCa {
            cn,
            vendor_id,
            out_cert,
            out_key,
            validity_years,
        } => {
            create_ca(&cn, vendor_id, &out_cert, &out_key, validity_years)?;
        }
        Commands::CreatePai {
            cn,
            vendor_id,
            ca_cert,
            ca_key,
            out_cert,
            out_key,
            validity_years,
        } => {
            create_pai(&cn, vendor_id, &ca_cert, &ca_key, &out_cert, &out_key, validity_years)?;
        }
        Commands::CreateDac {
            cn,
            vendor_id,
            product_id,
            ca_cert,
            ca_key,
            out_cert,
            out_key,
            validity_years,
        } => {
            create_dac(
                &cn,
                vendor_id,
                product_id,
                &ca_cert,
                &ca_key,
                &out_cert,
                &out_key,
                validity_years,
            )?;
        }
    }
    Ok(())
}
