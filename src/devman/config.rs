use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagerConfig {
    pub fabric_id: u64,
    pub controller_id: u64,
    pub local_address: String,
}

pub(crate) fn config_path(base: &str) -> String {
    format!("{}/config.json", base)
}

pub(crate) fn pem_path(base: &str) -> String {
    format!("{}/pem", base)
}

pub(crate) fn devices_path(base: &str) -> String {
    format!("{}/devices.json", base)
}

pub(crate) fn load_config(base: &str) -> Result<ManagerConfig> {
    let path = config_path(base);
    let data = std::fs::read_to_string(&path).context(format!("reading config from {}", path))?;
    serde_json::from_str(&data).context("parsing config.json")
}

pub(crate) fn save_config(base: &str, config: &ManagerConfig) -> Result<()> {
    let path = config_path(base);
    let data = serde_json::to_string_pretty(config)?;
    std::fs::write(&path, data).context(format!("writing config to {}", path))
}

