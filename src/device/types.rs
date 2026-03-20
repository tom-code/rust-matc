use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result};

use crate::{fabric, sigma, spake2p, tlv};

#[derive(Clone)]
pub struct DeviceConfig {
    pub pin: u32,
    pub discriminator: u16,
    pub listen_address: String,
    pub vendor_id: u16,
    pub product_id: u16,
    pub dac_cert_path: String,
    pub pai_cert_path: String,
    pub dac_key_path: String,
    pub hostname: String,
    /// If Some, load/save commissioned state from this directory.
    pub state_dir: Option<String>,
    pub vendor_name: String,
    pub product_name: String,
    pub hardware_version: u16,
    pub software_version: u32,
    pub serial_number: String,
    pub unique_id: String,
    /// IP addresses to advertise in mDNS A/AAAA records.
    /// When `None`, all local non-loopback addresses are advertised automatically.
    /// Each registered service (commissionable and per-fabric operational) will use these IPs.
    pub advertise_addresses: Option<Vec<std::net::IpAddr>>,
}

impl DeviceConfig {
    /// Split `advertise_addresses` into separate IPv4 and IPv6 lists for mDNS registration.
    /// Returns `(None, None)` when no override is configured (auto-detect fallback).
    pub fn split_advertise_ips(&self) -> (Option<Vec<Ipv4Addr>>, Option<Vec<Ipv6Addr>>) {
        match &self.advertise_addresses {
            None => (None, None),
            Some(addrs) => {
                let v4: Vec<Ipv4Addr> = addrs.iter().filter_map(|a| match a {
                    std::net::IpAddr::V4(ip) => Some(*ip),
                    _ => None,
                }).collect();
                let v6: Vec<Ipv6Addr> = addrs.iter().filter_map(|a| match a {
                    std::net::IpAddr::V6(ip) => Some(*ip),
                    _ => None,
                }).collect();
                (Some(v4), Some(v6))
            }
        }
    }
}

/// Serde helper: serialize `Vec<u8>` as a lowercase hex string.
mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

/// Serde helper: serialize `Option<Vec<u8>>` as an optional lowercase hex string.
mod hex_bytes_opt {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(b) => s.serialize_some(&hex::encode(b)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        let opt: Option<String> = Option::deserialize(d)?;
        opt.map(|s| hex::decode(&s).map_err(serde::de::Error::custom))
            .transpose()
    }
}

/// Per-fabric state in the persisted JSON.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct PersistedFabricState {
    pub fabric_index: u8,
    #[serde(with = "hex_bytes")]
    pub trusted_root_cert: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub noc: Vec<u8>,
    #[serde(with = "hex_bytes_opt")]
    pub icac: Option<Vec<u8>>,
    #[serde(with = "hex_bytes")]
    pub ipk: Vec<u8>,
    pub controller_id: u64,
    pub vendor_id: u16,
    #[serde(with = "hex_bytes")]
    pub device_matter_cert: Vec<u8>,
    pub label: String,
}

/// Full commissioned state serialized to disk.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct PersistedDeviceState {
    pub operational_key_hex: String,
    pub next_fabric_index: u8,
    pub fabrics: Vec<PersistedFabricState>,
    pub attribute_overrides: Vec<AttributeOverride>,
}

/// A single attribute value snapshot, encoded as hex TLV.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct AttributeOverride {
    pub endpoint: u16,
    pub cluster: u32,
    pub attribute: u32,
    pub tlv_hex: String,
}

pub(crate) struct PaseState {
    pub(crate) engine: spake2p::Engine,
    pub(crate) verifier: spake2p::Verifier,
    #[allow(dead_code)]
    pub(crate) exchange_id: u16,
    pub(crate) pbkdf_req_payload: Vec<u8>,
    pub(crate) pbkdf_resp_payload: Vec<u8>,
    pub(crate) responder_session_id: u16,
    pub(crate) initiator_session_id: u16,
}

pub(crate) struct CaseState {
    pub(crate) sigma2_ctx: sigma::Sigma2ResponseCtx,
    #[allow(dead_code)]
    pub(crate) exchange_id: u16,
    /// Which fabric is being established in this CASE exchange.
    pub(crate) fabric_index: u8,
}

/// Tracks which attributes a subscriber is watching.
#[derive(Clone)]
pub(crate) enum SubscribedPaths {
    /// Wildcard subscribe (no AttributeRequests in the subscribe message).
    All,
    /// Resolved concrete (endpoint, cluster, attribute) keys.
    Specific(Vec<(u16, u32, u32)>),
}

pub(crate) struct SubscribeState {
    pub(crate) exchange_id: u16,
    pub(crate) subscription_id: u32,
    pub(crate) paths: SubscribedPaths,
    pub(crate) max_interval_secs: u16,
}

pub(crate) struct ActiveSubscription {
    pub(crate) subscription_id: u32,
    pub(crate) session_id: u16,
    pub(crate) peer_addr: std::net::SocketAddr,
    pub(crate) max_interval_secs: u16,
    pub(crate) paths: SubscribedPaths,
}

pub(crate) struct PendingChunkState {
    pub(crate) exchange_id: u16,
    /// Reports not yet sent; drained from the front as chunks are dispatched.
    pub(crate) remaining: Vec<crate::device_messages::AttrReport>,
    pub(crate) subscription_id: Option<u32>,
}

pub(crate) struct FabricInfo {
    /// 1-based fabric index assigned at AddNOC time.
    pub(crate) fabric_index: u8,
    pub(crate) ipk: Vec<u8>,
    pub(crate) fabric: Option<fabric::Fabric>,
    pub(crate) device_matter_cert: Vec<u8>,
    pub(crate) controller_id: u64,
    pub(crate) vendor_id: u16,
    /// Root certificate (TLV-encoded Matter cert) — moved from Device.
    pub(crate) trusted_root_cert: Vec<u8>,
    /// Node Operational Certificate (TLV-encoded) — moved from Device.
    pub(crate) noc: Vec<u8>,
    /// Intermediate CA certificate, if provided.
    pub(crate) icac: Option<Vec<u8>>,
    pub(crate) label: String,
}

impl FabricInfo {
    /// Extract the CA public key (uncompressed SEC1) from the trusted root cert TLV.
    pub(crate) fn ca_public_key(&self) -> Result<Vec<u8>> {
        let decoded = tlv::decode_tlv(&self.trusted_root_cert)?;
        let pubkey = decoded
            .get_octet_string(&[9])
            .context("CA cert: public key (tag 9) missing")?;
        Ok(pubkey.to_vec())
    }

    fn noc_field(&self, tag_path: &[u8], field_name: &str) -> Result<u64> {
        let decoded = tlv::decode_tlv(&self.noc)?;
        decoded
            .get_int(tag_path)
            .with_context(|| format!("NOC: {} missing from subject", field_name))
    }

    pub(crate) fn fabric_id(&self) -> Result<u64> {
        self.noc_field(&[6u8, 21], "fabric_id")
    }

    pub(crate) fn device_node_id(&self) -> Result<u64> {
        self.noc_field(&[6u8, 17], "node_id")
    }

    pub(crate) fn ca_id(&self) -> Result<u64> {
        let decoded = tlv::decode_tlv(&self.trusted_root_cert)?;
        decoded
            .get_int(&[6, 20])
            .context("CA cert: ca_id missing from subject")
    }
}
