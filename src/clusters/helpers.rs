//! Helper functions for serializing Matter types to JSON
//!
//! This module provides serialization helpers for converting Matter TLV types
//! to JSON-friendly representations, particularly for octet strings which are
//! serialized as hexadecimal strings.

/// Serialize Option<Vec<u8>> as a hex string for JSON output
///
/// # Arguments
/// * `bytes` - Optional byte vector to serialize
/// * `serializer` - Serde serializer
///
/// # Returns
/// Serialized hex string or null if None
pub fn serialize_opt_bytes_as_hex<S>(bytes: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match bytes {
        Some(b) => {
            let hex_string = b.iter()
                .map(|byte| format!("{:02x}", byte))
                .collect::<String>();
            serializer.serialize_str(&hex_string)
        }
        None => serializer.serialize_none(),
    }
}

/// Serialize Vec<Vec<u8>> as an array of hex strings for JSON output
///
/// # Arguments
/// * `vec_bytes` - Vector of byte vectors to serialize
/// * `serializer` - Serde serializer
///
/// # Returns
/// Serialized array of hex strings
pub fn serialize_vec_bytes_as_hex<S>(vec_bytes: &Vec<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeSeq;
    let mut seq = serializer.serialize_seq(Some(vec_bytes.len()))?;
    for bytes in vec_bytes {
        let hex_string = bytes.iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<String>();
        seq.serialize_element(&hex_string)?;
    }
    seq.end()
}

/// Serialize Option<Vec<Vec<u8>>> as an array of hex strings for JSON output
///
/// # Arguments
/// * `vec_bytes` - Optional vector of byte vectors to serialize
/// * `serializer` - Serde serializer
///
/// # Returns
/// Serialized array of hex strings or null if None
pub fn serialize_opt_vec_bytes_as_hex<S>(vec_bytes: &Option<Vec<Vec<u8>>>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match vec_bytes {
        Some(v) => serialize_vec_bytes_as_hex(v, serializer),
        None => serializer.serialize_none(),
    }
}
