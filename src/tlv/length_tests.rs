use super::{decode_tlv, TlvItemValue};
use std::io::ErrorKind;

const VALUE_TYPES: [(u8, usize); 5] = [(0x0c, 1), (0x10, 1), (0x11, 2), (0x12, 4), (0x13, 8)];

fn encoded_value(kind: u8, width: usize, declared: u64, payload: &[u8]) -> Vec<u8> {
    let mut input = vec![kind];
    input.extend_from_slice(&declared.to_le_bytes()[..width]);
    input.extend_from_slice(payload);
    input
}

fn expected_value(kind: u8, payload: &[u8]) -> TlvItemValue {
    if kind == 0x0c {
        TlvItemValue::String(String::from_utf8(payload.to_vec()).unwrap())
    } else {
        TlvItemValue::OctetString(payload.to_vec())
    }
}

#[test]
fn test_decode_empty_length_values() {
    for (kind, width) in VALUE_TYPES {
        let input = encoded_value(kind, width, 0, &[]);
        assert_eq!(decode_tlv(&input).unwrap().value, expected_value(kind, &[]));
    }
}

#[test]
fn test_decode_exact_remaining_length_values() {
    let payload = b"value";
    for (kind, width) in VALUE_TYPES {
        let input = encoded_value(kind, width, payload.len() as u64, payload);
        assert_eq!(
            decode_tlv(&input).unwrap().value,
            expected_value(kind, payload)
        );
    }
}

#[test]
fn test_decode_truncated_length_fields() {
    for (kind, width) in VALUE_TYPES {
        let input = encoded_value(kind, width, 1, &[]);
        for length_bytes in 0..width {
            assert_eq!(
                decode_tlv(&input[..1 + length_bytes]).unwrap_err().kind(),
                ErrorKind::UnexpectedEof,
                "kind={kind:#x}, length_bytes={length_bytes}",
            );
        }
    }
}

#[test]
fn test_decode_length_exceeding_remaining_input() {
    for (kind, width) in VALUE_TYPES {
        for payload in [&b""[..], &b"a"[..], &b"abc"[..]] {
            let input = encoded_value(kind, width, 4, payload);
            assert_eq!(
                decode_tlv(&input).unwrap_err().kind(),
                ErrorKind::UnexpectedEof,
                "kind={kind:#x}, remaining={}",
                payload.len(),
            );
        }
    }
}

#[test]
fn test_decode_maximum_declared_lengths_without_payload() {
    for (kind, width) in VALUE_TYPES {
        let declared = match width {
            1 => u64::from(u8::MAX),
            2 => u64::from(u16::MAX),
            4 => u64::from(u32::MAX),
            8 => u64::MAX,
            _ => unreachable!(),
        };
        let input = encoded_value(kind, width, declared, &[]);
        assert_eq!(
            decode_tlv(&input).unwrap_err().kind(),
            ErrorKind::UnexpectedEof,
            "kind={kind:#x}",
        );
    }
}

#[test]
fn test_decode_large_declared_lengths_without_payload() {
    for (kind, width) in [(0x12, 4), (0x13, 8)] {
        let input = encoded_value(kind, width, 2_080_522_737, &[]);
        assert_eq!(
            decode_tlv(&input).unwrap_err().kind(),
            ErrorKind::UnexpectedEof,
        );
    }
}

#[test]
fn test_decode_length_value_preserves_following_element() {
    for (kind, width) in VALUE_TYPES {
        let mut input = vec![0x15];
        input.push(kind | 0x20);
        input.push(1);
        input.extend_from_slice(&encoded_value(kind, width, 2, b"ok")[1..]);
        input.extend_from_slice(&[0x24, 2, 7, 0x18]);
        let decoded = decode_tlv(&input).unwrap();
        assert_eq!(decoded.get(&[1]), Some(&expected_value(kind, b"ok")));
        assert_eq!(decoded.get_int(&[2]), Some(7));
    }
}

#[test]
fn test_decode_valid_large_values_without_transport_cap() {
    let payload = vec![0x5a; 65_536];
    for (kind, width) in [(0x12, 4), (0x13, 8)] {
        let input = encoded_value(kind, width, payload.len() as u64, &payload);
        let decoded = decode_tlv(&input).unwrap();
        assert_eq!(decoded.get_octet_string(&[]), Some(payload.as_slice()));
    }
}

#[test]
fn test_decode_invalid_utf8_value_preserves_invalid_result() {
    let input = encoded_value(0x0c, 1, 1, &[0xff]);
    assert_eq!(decode_tlv(&input).unwrap().value, TlvItemValue::Invalid());
}
