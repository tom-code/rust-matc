use anyhow::{bail, Context, Result};

/// Bitfield flags for discovery capabilities returned from QR code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscoveryCapabilities(pub u8);

impl DiscoveryCapabilities {
    pub fn has_soft_ap(self) -> bool { self.0 & 0x01 != 0 }
    pub fn has_ble(self) -> bool { self.0 & 0x02 != 0 }
    pub fn has_on_network(self) -> bool { self.0 & 0x04 != 0 }
}

#[derive(Debug)]
pub struct OnboardingInfo {
    pub discriminator: u16,
    pub passcode: u32,
    /// True when decoded from a manual pairing code (only top 4 bits of discriminator are valid).
    pub is_short_discriminator: bool,
    /// Present only when decoded from a QR code payload.
    pub vendor_id: Option<u16>,
    /// Present only when decoded from a QR code payload.
    pub product_id: Option<u16>,
    /// Present only when decoded from a QR code payload.
    pub discovery_capabilities: Option<DiscoveryCapabilities>,
}

/// Base38 alphabet used in Matter QR codes (no space; ends with `-` and `.`).
const BASE38_CHARS: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-.";

fn base38_val(ch: char) -> Result<u32> {
    BASE38_CHARS
        .iter()
        .position(|&c| c == ch as u8)
        .map(|p| p as u32)
        .ok_or_else(|| anyhow::anyhow!("invalid Base38 character '{}'", ch))
}

/// Decode a Base38 string into bytes.
///
/// Per the Matter spec, Base38 encodes input bytes in chunks of 3 bytes → 5
/// chars (little-endian, char 0 carrying the least-significant base-38 digit).
/// Trailing groups are: 4 chars → 2 bytes, 2 chars → 1 byte. Any other
/// trailing length is invalid.
fn base38_decode(s: &str) -> Result<Vec<u8>> {
    const CHARS_PER_CHUNK: usize = 5;
    const BYTES_PER_CHUNK: usize = 3;

    let chars: Vec<char> = s.chars().collect();
    let n = chars.len();
    let trailing = n % CHARS_PER_CHUNK;
    let trailing_bytes = match trailing {
        0 => 0,
        2 => 1,
        4 => 2,
        _ => bail!(
            "invalid Base38 length {}: trailing chars must be 0, 2, or 4 (mod 5)",
            n
        ),
    };

    let full_chunks = n / CHARS_PER_CHUNK;
    let mut out = Vec::with_capacity(full_chunks * BYTES_PER_CHUNK + trailing_bytes);

    let decode_group = |chars_slice: &[char]| -> Result<u32> {
        let mut v: u32 = 0;
        for c in chars_slice.iter().rev() {
            v = v * 38 + base38_val(*c)?;
        }
        Ok(v)
    };

    for chunk in 0..full_chunks {
        let i = chunk * CHARS_PER_CHUNK;
        let v = decode_group(&chars[i..i + CHARS_PER_CHUNK])?;
        out.push((v & 0xff) as u8);
        out.push(((v >> 8) & 0xff) as u8);
        out.push(((v >> 16) & 0xff) as u8);
    }

    if trailing > 0 {
        let i = full_chunks * CHARS_PER_CHUNK;
        let v = decode_group(&chars[i..i + trailing])?;
        for b in 0..trailing_bytes {
            out.push(((v >> (b * 8)) & 0xff) as u8);
        }
    }

    Ok(out)
}

/// Decode a Matter QR code payload (the `MT:...` string, with or without the `MT:` prefix).
///
/// The payload is a Base38-encoded 88-bit integer with the following layout (LSB first):
/// * bits  0- 2 : version (3 bits)
/// * bits  3-18 : vendor ID (16 bits)
/// * bits 19-34 : product ID (16 bits)
/// * bits 35-36 : commissioning flow (2 bits)
/// * bits 37-44 : discovery capabilities (8 bits)
/// * bits 45-56 : discriminator (12 bits)
/// * bits 57-83 : passcode (27 bits)
/// * bits 84-87 : padding (4 bits, must be zero)
pub fn decode_qr_payload(qr: &str) -> Result<OnboardingInfo> {
    let payload = qr.trim().strip_prefix("MT:").unwrap_or(qr.trim());
    let bytes = base38_decode(payload).context("base38 decode")?;
    if bytes.len() < 11 {
        bail!("QR payload too short: {} bytes", bytes.len());
    }

    // Pack into a 88-bit little-endian integer (11 bytes)
    let mut bits: u128 = 0;
    for (i, &b) in bytes.iter().take(11).enumerate() {
        bits |= (b as u128) << (i * 8);
    }

    let _version          = (bits & 0x7) as u8;
    let vendor_id         = ((bits >> 3) & 0xffff) as u16;
    let product_id        = ((bits >> 19) & 0xffff) as u16;
    let _custom_flow      = ((bits >> 35) & 0x3) as u8;
    let disc_caps         = ((bits >> 37) & 0xff) as u8;
    let discriminator     = ((bits >> 45) & 0xfff) as u16;
    let passcode          = ((bits >> 57) & 0x7ff_ffff) as u32;

    Ok(OnboardingInfo {
        discriminator,
        passcode,
        is_short_discriminator: false,
        vendor_id: Some(vendor_id),
        product_id: Some(product_id),
        discovery_capabilities: Some(DiscoveryCapabilities(disc_caps)),
    })
}

pub fn decode_manual_pairing_code(code: &str) -> Result<OnboardingInfo> {
    let norm = code.replace("-", "");
    let first_grp = &norm[0..1];
    let second_grp = &norm[1..6];
    let third_grp = &norm[6..10];
    let first = first_grp.parse::<u32>()?;
    let second = second_grp.parse::<u32>()?;
    let third = third_grp.parse::<u32>()?;
    let passcode = second & 0x3fff | (third << 14);
    let discriminator = (((first & 3) << 10) | (second >> 6) & 0x300) as u16;
    Ok(OnboardingInfo {
        discriminator,
        passcode,
        is_short_discriminator: true,
        vendor_id: None,
        product_id: None,
        discovery_capabilities: None,
    })
}

static D: [[u8; 10]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];

/// The permutation table.
static P: [[u8; 10]; 8] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

/// Inverse table for Verhoeff's dihedral group D5.
static INV: [u8; 10] = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9];

fn verhoeff_checksum(num: &str) -> u8 {
    let mut c: usize = 0;
    for (i, ch) in num.chars().rev().enumerate() {
        let digit = ch.to_digit(10).unwrap() as usize;
        c = D[c][P[(i + 1) % 8][digit] as usize] as usize;
    }
    INV[c]
}

pub fn encode_manual_pairing_code(info: &OnboardingInfo) -> String {
    let first = (info.discriminator as u32 >> 10) as u8;
    let second = ((info.discriminator & 0x300) << 6) as u32 | (info.passcode & 0x3fff);
    let third = info.passcode >> 14;
    let digits = format!("{:01}{:05}{:04}", first, second, third);
    let check = verhoeff_checksum(&digits);
    let num = format!("{}{:05}{:04}{}", first, second, third, check);
    // Insert dashes after each 4th digit
    let mut formatted = String::new();
    for (i, ch) in num.chars().enumerate() {
        if i > 0 && i % 4 == 0 {
            formatted.push('-');
        }
        formatted.push(ch);
    }
    formatted
}

#[cfg(test)]
mod tests {
    use crate::onboarding::OnboardingInfo;

    use super::decode_manual_pairing_code;
    use super::encode_manual_pairing_code;

    #[test]
    pub fn test_1() {
        let res = decode_manual_pairing_code("2585-103-3238").unwrap();
        assert_eq!(res.discriminator, 2816);
        assert_eq!(res.passcode, 54453390);
        let encoded = encode_manual_pairing_code(&res);
        assert_eq!(encoded.replace("-", ""), "25851033238");
    }

    #[test]
    pub fn test_2() {
        let res = decode_manual_pairing_code("34970112332").unwrap();
        assert_eq!(res.discriminator, 3840);
        assert_eq!(res.passcode, 20202021);
        let encoded = encode_manual_pairing_code(&res);
        assert_eq!(encoded.replace("-", ""), "34970112332");
    }
    #[test]
    pub fn test_3() {
        let oi = OnboardingInfo {
            discriminator: 3840,
            passcode: 123456,
            is_short_discriminator: false,
            vendor_id: None,
            product_id: None,
            discovery_capabilities: None,
        };
        let encoded = encode_manual_pairing_code(&oi);
        println!("Encoded: {}", encoded);
    }

    /// QR from `chip-lighting-app --passcode 123456 --discriminator 100`
    /// (default vendor 0xFFF1 / product 0x8001).
    #[test]
    pub fn test_qr_decode() {
        let info = super::decode_qr_payload("MT:-24J04QI14G6Q663000").unwrap();
        assert_eq!(info.passcode, 123456, "passcode mismatch");
        assert_eq!(info.discriminator, 100, "discriminator mismatch");
        assert_eq!(info.vendor_id, Some(0xFFF1));
        assert_eq!(info.product_id, Some(0x8001));
        let dc = info.discovery_capabilities.unwrap();
        assert!(dc.has_on_network());
    }

    /// Same default vendor/product as `test_qr_decode`, but with
    /// passcode 123456 and discriminator 4095 (all 12 bits set).
    #[test]
    pub fn test_qr_decode2() {
        let info = super::decode_qr_payload("MT:-24J0SO527LJQ663000").unwrap();
        assert_eq!(info.passcode, 123456, "passcode mismatch");
        assert_eq!(info.discriminator, 4095, "discriminator mismatch");
        assert_eq!(info.vendor_id, Some(0xFFF1));
        assert_eq!(info.product_id, Some(0x8001));
        let dc = info.discovery_capabilities.unwrap();
        assert!(dc.has_on_network());
    }
}
