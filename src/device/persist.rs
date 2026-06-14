use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::AtomicU32;

use anyhow::{Context, Result};

use crate::fabric;

use super::Device;
use super::types::{AttributeOverride, DeviceConfig, FabricInfo, PersistedDeviceState, PersistedFabricState};

static PERSISTED_ATTRIBUTES: &[(u16, u32, u32)] = &[];

impl Device {
    pub(crate) fn collect_attribute_overrides(&self) -> Vec<AttributeOverride> {
        let mut overrides = Vec::new();
        for &(endpoint, cluster, attribute) in PERSISTED_ATTRIBUTES.iter().chain(self.extra_persisted.iter()) {
            if let Some(tlv) = self.attributes.get(&(endpoint, cluster, attribute)) {
                overrides.push(AttributeOverride {
                    endpoint,
                    cluster,
                    attribute,
                    tlv_hex: hex::encode(tlv),
                });
            }
        }
        overrides
    }

    /// Register an additional attribute key to include in persistence.
    pub fn add_persisted_attribute(&mut self, endpoint: u16, cluster: u32, attribute: u32) {
        let key = (endpoint, cluster, attribute);
        if !self.extra_persisted.contains(&key) {
            self.extra_persisted.push(key);
        }
    }

    /// Persist current commissioned state to `{state_dir}/device_state.json`.
    pub(crate) fn save_state(&self, state_dir: &str) -> Result<()> {
        if self.fabrics.is_empty() {
            let path = format!("{}/device_state.json", state_dir);
            if std::path::Path::new(&path).exists() {
                std::fs::remove_file(&path)?;
                log::info!("All fabrics removed - deleted {}", path);
            }
            return Ok(());
        }

        let fabrics: Vec<PersistedFabricState> = self
            .fabrics
            .iter()
            .map(|fi| PersistedFabricState {
                fabric_index: fi.fabric_index,
                trusted_root_cert: fi.trusted_root_cert.clone(),
                noc: fi.noc.clone(),
                icac: fi.icac.clone(),
                ipk: fi.ipk.clone(),
                controller_id: fi.controller_id,
                vendor_id: fi.vendor_id,
                device_matter_cert: fi.device_matter_cert.clone(),
                label: fi.label.clone(),
            })
            .collect();

        let state = PersistedDeviceState {
            operational_key_hex: hex::encode(self.operational_key.to_bytes()),
            next_fabric_index: self.next_fabric_index,
            fabrics,
            attribute_overrides: self.collect_attribute_overrides(),
        };

        std::fs::create_dir_all(state_dir)?;
        let path = format!("{}/device_state.json", state_dir);
        let json = serde_json::to_string_pretty(&state)?;
        std::fs::write(&path, json)?;
        log::info!("Device state saved to {}", path);
        Ok(())
    }

    /// Register the operational `_matter._tcp.local` mDNS service for one fabric.
    /// `fabric_idx` is an index into `self.fabrics`.
    pub(crate) async fn register_operational_mdns(&self, fabric_idx: usize) -> Result<()> {
        let fi = &self.fabrics[fabric_idx];
        let nod_id = fi.device_node_id()?;
        let ca_public_key = fi.ca_public_key()?;
        let fabric_id = fi.fabric_id()?;
        let ca_id = fi.ca_id()?;
        let fabric = fabric::Fabric::new(fabric_id, ca_id, &ca_public_key, &fi.ipk);

        let iname = format!(
            "{}-{:016X}",
            hex::encode_upper(fabric.compressed()?),
            nod_id
        );
        let op_port: u16 = self
            .config
            .listen_address
            .rsplit(':')
            .next()
            .and_then(|p| p.parse().ok())
            .unwrap_or(5540);
        let (adv_v4, adv_v6) = self.config.split_advertise_ips();
        let svc = crate::mdns2::ServiceRegistration {
            instance_name: iname,
            service_type: "_matter._tcp.local".to_string(),
            port: op_port,
            txt_records: vec![
                ("SII".to_string(), "500".to_string()),
                ("SAI".to_string(), "300".to_string()),
            ],
            hostname: self.config.hostname.clone(),
            ttl: 120,
            subtypes: vec![],
            ips_v4: adv_v4,
            ips_v6: adv_v6,
        };
        self.mdns.register_service(svc).await;
        Ok(())
    }

    /// Restore a previously commissioned device from `{state_dir}/device_state.json`.
    ///
    /// On success the device is ready to accept CASE sessions - it will NOT re-advertise
    /// the commissionable `_matterc._udp` service.
    pub async fn from_persisted_state(
        config: DeviceConfig,
        mdns: Arc<crate::mdns2::MdnsService>,
        state_dir: &str,
    ) -> Result<Self> {
        let path = format!("{}/device_state.json", state_dir);
        let json = std::fs::read_to_string(&path)
            .with_context(|| format!("Cannot read persisted state from {}", path))?;
        let state: PersistedDeviceState = serde_json::from_str(&json)?;

        // Restore P-256 operational key from hex-encoded scalar bytes.
        let key_bytes = hex::decode(&state.operational_key_hex)
            .context("Invalid hex in operational_key_hex")?;
        let operational_key = p256::SecretKey::from_slice(&key_bytes)
            .context("Invalid P-256 scalar in persisted operational key")?;

        let socket = tokio::net::UdpSocket::bind(&config.listen_address).await?;

        let mut salt = vec![0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);

        let fabrics: Vec<FabricInfo> = state
            .fabrics
            .iter()
            .map(|pf| FabricInfo {
                fabric_index: pf.fabric_index,
                ipk: pf.ipk.clone(),
                fabric: None,
                device_matter_cert: pf.device_matter_cert.clone(),
                controller_id: pf.controller_id,
                vendor_id: pf.vendor_id,
                trusted_root_cert: pf.trusted_root_cert.clone(),
                noc: pf.noc.clone(),
                icac: pf.icac.clone(),
                label: pf.label.clone(),
            })
            .collect();

        let mut device = Self {
            config,
            socket,
            salt,
            pbkdf_iterations: 1000,
            operational_key,
            message_counter: AtomicU32::new(crate::util::cryptoutil::initial_message_counter()),
            pase_state: None,
            pase_session: None,
            case_states: HashMap::new(),
            case_sessions: Vec::new(),
            subscribe_states: Vec::new(),
            active_subscriptions: Vec::new(),
            pending_chunks: Vec::new(),
            fabrics,
            next_fabric_index: state.next_fabric_index,
            pending_root_cert: None,
            unencrypted_reception: HashMap::new(),
            endpoints: vec![0],
            attributes: HashMap::new(),
            dirty_attributes: HashSet::new(),
            mdns,
            extra_persisted: Vec::new(),
        };

        device.setup_default_attributes()?;

        // Overlay persisted attribute values on top of the defaults.
        // Old JSON files may still contain Fabrics/CommissionedFabrics entries here;
        // they are overwritten by rebuild_fabrics_attribute() below.
        for ov in &state.attribute_overrides {
            let tlv = hex::decode(&ov.tlv_hex)
                .with_context(|| format!("Bad tlv_hex for ({},{},{})", ov.endpoint, ov.cluster, ov.attribute))?;
            device.attributes.insert((ov.endpoint, ov.cluster, ov.attribute), tlv);
        }

        // Rebuild Fabrics and CommissionedFabrics from the restored fabric list.
        device.rebuild_fabrics_attribute()?;
        device.dirty_attributes.clear();

        // Re-register operational mDNS for each fabric.
        for i in 0..device.fabrics.len() {
            device.register_operational_mdns(i).await?;
        }

        log::info!(
            "Device state restored from {} ({} fabric(s))",
            path,
            device.fabrics.len()
        );
        Ok(device)
    }
}
