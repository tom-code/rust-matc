use anyhow::Result;

#[derive(Debug)]
pub struct OnboardingInfo {
    pub discriminator: u16,
    pub passcode: u32,
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
        };
        let encoded = encode_manual_pairing_code(&oi);
        println!("Encoded: {}", encoded);
    }
}
