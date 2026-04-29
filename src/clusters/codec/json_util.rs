// Helper functions for extracting typed values from serde_json::Value objects
// used by the generated encode_command_json functions.

use anyhow;

pub fn get_u8(args: &serde_json::Value, name: &str) -> anyhow::Result<u8> {
    args.get(name)
        .and_then(|v| v.as_u64())
        .map(|n| n as u8)
        .ok_or_else(|| anyhow::anyhow!("missing or invalid field: {}", name))
}

pub fn get_u16(args: &serde_json::Value, name: &str) -> anyhow::Result<u16> {
    args.get(name)
        .and_then(|v| v.as_u64())
        .map(|n| n as u16)
        .ok_or_else(|| anyhow::anyhow!("missing or invalid field: {}", name))
}

pub fn get_u32(args: &serde_json::Value, name: &str) -> anyhow::Result<u32> {
    args.get(name)
        .and_then(|v| v.as_u64())
        .map(|n| n as u32)
        .ok_or_else(|| anyhow::anyhow!("missing or invalid field: {}", name))
}

pub fn get_u64(args: &serde_json::Value, name: &str) -> anyhow::Result<u64> {
    args.get(name)
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow::anyhow!("missing or invalid field: {}", name))
}

pub fn get_i8(args: &serde_json::Value, name: &str) -> anyhow::Result<i8> {
    args.get(name)
        .and_then(|v| v.as_i64())
        .map(|n| n as i8)
        .ok_or_else(|| anyhow::anyhow!("missing or invalid field: {}", name))
}

pub fn get_i16(args: &serde_json::Value, name: &str) -> anyhow::Result<i16> {
    args.get(name)
        .and_then(|v| v.as_i64())
        .map(|n| n as i16)
        .ok_or_else(|| anyhow::anyhow!("missing or invalid field: {}", name))
}

pub fn get_i32(args: &serde_json::Value, name: &str) -> anyhow::Result<i32> {
    args.get(name)
        .and_then(|v| v.as_i64())
        .map(|n| n as i32)
        .ok_or_else(|| anyhow::anyhow!("missing or invalid field: {}", name))
}

pub fn get_i64(args: &serde_json::Value, name: &str) -> anyhow::Result<i64> {
    args.get(name)
        .and_then(|v| v.as_i64())
        .ok_or_else(|| anyhow::anyhow!("missing or invalid field: {}", name))
}

pub fn get_bool(args: &serde_json::Value, name: &str) -> anyhow::Result<bool> {
    args.get(name)
        .and_then(|v| v.as_bool())
        .ok_or_else(|| anyhow::anyhow!("missing or invalid field: {}", name))
}

pub fn get_string(args: &serde_json::Value, name: &str) -> anyhow::Result<String> {
    args.get(name)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("missing or invalid field: {}", name))
}

// Accepts a hex string and decodes it to bytes.
pub fn get_octstr(args: &serde_json::Value, name: &str) -> anyhow::Result<Vec<u8>> {
    let s = args.get(name)
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing or invalid field: {}", name))?;
    let s = s.replace(' ', "");
    hex::decode(&s).map_err(|e| anyhow::anyhow!("field {}: invalid hex: {}", name, e))
}

// Optional variants - return None when the field is absent or null.
pub fn get_opt_u8(args: &serde_json::Value, name: &str) -> anyhow::Result<Option<u8>> {
    match args.get(name) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(v) => v.as_u64()
            .map(|n| Some(n as u8))
            .ok_or_else(|| anyhow::anyhow!("invalid field: {}", name)),
    }
}

pub fn get_opt_u16(args: &serde_json::Value, name: &str) -> anyhow::Result<Option<u16>> {
    match args.get(name) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(v) => v.as_u64()
            .map(|n| Some(n as u16))
            .ok_or_else(|| anyhow::anyhow!("invalid field: {}", name)),
    }
}

pub fn get_opt_u32(args: &serde_json::Value, name: &str) -> anyhow::Result<Option<u32>> {
    match args.get(name) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(v) => v.as_u64()
            .map(|n| Some(n as u32))
            .ok_or_else(|| anyhow::anyhow!("invalid field: {}", name)),
    }
}

pub fn get_opt_u64(args: &serde_json::Value, name: &str) -> anyhow::Result<Option<u64>> {
    match args.get(name) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(v) => v.as_u64()
            .map(Some)
            .ok_or_else(|| anyhow::anyhow!("invalid field: {}", name)),
    }
}

pub fn get_opt_i8(args: &serde_json::Value, name: &str) -> anyhow::Result<Option<i8>> {
    match args.get(name) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(v) => v.as_i64()
            .map(|n| Some(n as i8))
            .ok_or_else(|| anyhow::anyhow!("invalid field: {}", name)),
    }
}

pub fn get_opt_i16(args: &serde_json::Value, name: &str) -> anyhow::Result<Option<i16>> {
    match args.get(name) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(v) => v.as_i64()
            .map(|n| Some(n as i16))
            .ok_or_else(|| anyhow::anyhow!("invalid field: {}", name)),
    }
}

pub fn get_opt_i32(args: &serde_json::Value, name: &str) -> anyhow::Result<Option<i32>> {
    match args.get(name) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(v) => v.as_i64()
            .map(|n| Some(n as i32))
            .ok_or_else(|| anyhow::anyhow!("invalid field: {}", name)),
    }
}

pub fn get_opt_i64(args: &serde_json::Value, name: &str) -> anyhow::Result<Option<i64>> {
    match args.get(name) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(v) => v.as_i64()
            .map(Some)
            .ok_or_else(|| anyhow::anyhow!("invalid field: {}", name)),
    }
}

pub fn get_opt_bool(args: &serde_json::Value, name: &str) -> anyhow::Result<Option<bool>> {
    match args.get(name) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(v) => v.as_bool()
            .map(Some)
            .ok_or_else(|| anyhow::anyhow!("invalid field: {}", name)),
    }
}

pub fn get_opt_string(args: &serde_json::Value, name: &str) -> anyhow::Result<Option<String>> {
    match args.get(name) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(v) => v.as_str()
            .map(|s| Some(s.to_string()))
            .ok_or_else(|| anyhow::anyhow!("invalid field: {}", name)),
    }
}

pub fn get_opt_octstr(args: &serde_json::Value, name: &str) -> anyhow::Result<Option<Vec<u8>>> {
    match args.get(name) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(v) => {
            let s = v.as_str().ok_or_else(|| anyhow::anyhow!("invalid field: {}", name))?;
            let s = s.replace(' ', "");
            hex::decode(&s)
                .map(Some)
                .map_err(|e| anyhow::anyhow!("field {}: invalid hex: {}", name, e))
        }
    }
}
