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

#[cfg(test)]
mod tests {
    use super::decode_manual_pairing_code;

    #[test]
    pub fn test_1() {
        let res = decode_manual_pairing_code("2585-103-3238").unwrap();
        assert_eq!(res.discriminator, 2816);
        assert_eq!(res.passcode, 54453390);
    }

    #[test]
    pub fn test_2() {
        let res = decode_manual_pairing_code("34970112332").unwrap();
        assert_eq!(res.discriminator, 3840);
        assert_eq!(res.passcode, 20202021);
    }
}
