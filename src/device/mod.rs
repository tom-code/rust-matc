//! very experimental device implementation with many things hardcoded for testing and development purposes.

mod attributes;
mod case_handler;
mod commissioning;
mod crypto;
mod interaction;
mod pase;
mod persist;
mod send;
mod types;

pub use types::DeviceConfig;
pub use attributes::AttrContext;
use types::{ActiveSubscription, CaseState, FabricInfo, PaseState, PendingChunkState, SubscribeState};


use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use anyhow::{Ok, Result};
use tokio::net::UdpSocket;

use crate::{messages, session, tlv};

/// Result returned by [`AppHandler::handle_command`].
pub enum CommandResult {
    /// Command succeeded; library will send an IM status response with status 0.
    Success,
    /// Command failed with the given status code.
    Error(u16),
    /// Command is not handled by this application handler.
    Unhandled,
}

pub trait AppHandler: Send {
    fn handle_command(
        &mut self,
        endpoint: u16,
        cluster: u32,
        command: u32,
        payload: &tlv::TlvItem,
        attrs: &mut AttrContext,
    ) -> CommandResult;
}

pub struct Device {
    pub(crate) config: DeviceConfig,
    pub(crate) socket: UdpSocket,
    pub(crate) salt: Vec<u8>,
    pub(crate) pbkdf_iterations: u32,
    pub(crate) operational_key: p256::SecretKey,
    pub(crate) message_counter: AtomicU32,
    // Commissioning state
    pub(crate) pase_state: Option<PaseState>,
    pub(crate) pase_session: Option<session::Session>,
    pub(crate) case_states: HashMap<u16, CaseState>,
    pub(crate) case_sessions: Vec<session::Session>,
    pub(crate) subscribe_states: Vec<SubscribeState>,
    pub(crate) active_subscriptions: Vec<ActiveSubscription>,
    pub(crate) pending_chunks: Vec<PendingChunkState>,
    // Commissioned fabric table (supports multiple fabrics)
    pub(crate) fabrics: Vec<FabricInfo>,
    /// Next fabric index to assign (1-based, monotonically increasing).
    pub(crate) next_fabric_index: u8,
    /// Temporary root cert from AddTrustedRootCertificate, consumed by AddNOC.
    pub(crate) pending_root_cert: Option<Vec<u8>>,
    // Duplicate detection
    pub(crate) received_counters: HashSet<u32>,
    /// Registered application endpoints (EP0 is always present).
    pub(crate) endpoints: Vec<u16>,
    // Attribute store: (endpoint, cluster, attribute) -> pre-tagged TLV at context tag 2
    pub(crate) attributes: HashMap<(u16, u32, u32), Vec<u8>>,
    /// Attributes mutated since last subscription report was sent.
    pub(crate) dirty_attributes: HashSet<(u16, u32, u32)>,
    pub(crate) mdns: Arc<crate::mdns2::MdnsService>,
    /// Extra attributes to include in persistence (registered by user code).
    pub(crate) extra_persisted: Vec<(u16, u32, u32)>,
}

impl Device {
    pub async fn new(config: DeviceConfig, mdns: Arc<crate::mdns2::MdnsService>) -> Result<Self> {
        let socket = UdpSocket::bind(&config.listen_address).await?;
        let mut salt = vec![0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);
        let operational_key = p256::SecretKey::random(&mut rand::thread_rng());
        let mut device = Self {
            config,
            socket,
            salt,
            pbkdf_iterations: 1000,
            operational_key,
            message_counter: AtomicU32::new(rand::random()),
            pase_state: None,
            pase_session: None,
            case_states: HashMap::new(),
            case_sessions: Vec::new(),
            subscribe_states: Vec::new(),
            active_subscriptions: Vec::new(),
            pending_chunks: Vec::new(),
            fabrics: Vec::new(),
            next_fabric_index: 1,
            pending_root_cert: None,
            received_counters: HashSet::new(),
            endpoints: vec![0],
            attributes: HashMap::new(),
            dirty_attributes: HashSet::new(),
            mdns,
            extra_persisted: Vec::new(),
        };
        device.setup_default_attributes()?;
        device.dirty_attributes.clear();

        // Register mDNS commissionable service advertisement
        let port: u16 = device
            .config
            .listen_address
            .rsplit(':')
            .next()
            .and_then(|p| p.parse().ok())
            .unwrap_or(5540);
        let short_disc = device.config.discriminator >> 8;
        let instance_name = format!("{:016X}", rand::random::<u64>());
        let (adv_v4, adv_v6) = device.config.split_advertise_ips();
        let svc = crate::mdns2::ServiceRegistration {
            instance_name,
            service_type: "_matterc._udp.local".to_string(),
            port,
            txt_records: vec![
                ("DN".to_string(), device.config.product_name.clone()),
                ("D".to_string(), device.config.discriminator.to_string()),
                (
                    "VP".to_string(),
                    format!("{}+{}", device.config.vendor_id, device.config.product_id),
                ),
                ("CM".to_string(), "1".to_string()),
                ("PH".to_string(), "33".to_string()),
                ("DT".to_string(), "256".to_string()),
            ],
            hostname: device.config.hostname.clone(),
            ttl: 120,
            subtypes: vec![format!("_S{}", short_disc)],
            ips_v4: adv_v4,
            ips_v6: adv_v6,
        };
        device.mdns.register_service(svc).await;

        Ok(device)
    }

    pub(crate) fn next_counter(&self) -> u32 {
        self.message_counter.fetch_add(1, Ordering::Relaxed)
    }

    pub async fn run(&mut self, handler: &mut dyn AppHandler) -> Result<()> {
        let mut buf = [0u8; 4096];
        log::info!(
            "Device listening on {} (PIN: {})",
            self.config.listen_address,
            self.config.pin
        );
        loop {
            let max_interval = self
                .active_subscriptions
                .iter()
                .map(|sub| sub.max_interval_secs as u64)
                .min()
                .map(std::time::Duration::from_secs)
                .unwrap_or_else(|| std::time::Duration::from_secs(3600));
            let has_dirty = !self.dirty_attributes.is_empty();
            tokio::select! {
                result = self.socket.recv_from(&mut buf) => {
                    let (len, addr) = result?;
                    let data = buf[..len].to_vec();
                    if let Err(e) = self.handle_packet(&data, &addr, handler).await {
                        log::warn!("Error handling packet from {}: {:?}", addr, e);
                    }
                }
                _ = tokio::time::sleep(max_interval) => {
                    if let Err(e) = self.send_subscription_report().await {
                        log::warn!("Error sending subscription keepalive: {:?}", e);
                    }
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(1)), if has_dirty => {
                    if let Err(e) = self.send_subscription_report().await {
                        log::warn!("Error sending dirty subscription report: {:?}", e);
                    }
                }
            }
        }
    }

    async fn handle_packet(&mut self, data: &[u8], addr: &std::net::SocketAddr, handler: &mut dyn AppHandler) -> Result<()> {
        let (msg_header, rest) = messages::MessageHeader::decode(data)?;
        log::debug!(
            "Received message: session={} counter={} from {}",
            msg_header.session_id,
            msg_header.message_counter,
            addr
        );

        // Duplicate detection
        if self.received_counters.contains(&msg_header.message_counter) {
            log::debug!(
                "Dropping duplicate message counter={}",
                msg_header.message_counter
            );
            return Ok(());
        }
        self.received_counters.insert(msg_header.message_counter);

        // Try to decrypt if we have a session
        let payload = if msg_header.session_id != 0 {
            // Encrypted message - search CASE sessions, then PASE
            let session = self
                .case_sessions
                .iter()
                .find(|s| s.my_session_id == msg_header.session_id)
                .or_else(|| {
                    self.pase_session
                        .as_ref()
                        .filter(|s| s.my_session_id == msg_header.session_id)
                });
            match session {
                Some(ses) => {
                    let decrypted = ses.decode_message(data)?;
                    let (_, proto_rest) = messages::MessageHeader::decode(&decrypted)?;
                    proto_rest
                }
                None => {
                    log::debug!(
                        "No session for session_id={}, dropping",
                        msg_header.session_id
                    );
                    return Ok(());
                }
            }
        } else {
            rest
        };

        let (proto_header, proto_payload) = messages::ProtocolMessageHeader::decode(&payload)?;
        log::debug!(
            "Protocol: opcode=0x{:02x} protocol={} exchange={} flags=0x{:02x}",
            proto_header.opcode,
            proto_header.protocol_id,
            proto_header.exchange_id,
            proto_header.exchange_flags
        );

        // Handle ACKs - just ignore
        if proto_header.protocol_id == messages::ProtocolMessageHeader::PROTOCOL_ID_SECURE_CHANNEL
            && proto_header.opcode == messages::ProtocolMessageHeader::OPCODE_ACK
        {
            return Ok(());
        }

        match (proto_header.protocol_id, proto_header.opcode) {
            (
                messages::ProtocolMessageHeader::PROTOCOL_ID_SECURE_CHANNEL,
                messages::ProtocolMessageHeader::OPCODE_PBKDF_REQ,
            ) => {
                self.handle_pbkdf_req(addr, &msg_header, &proto_header, &proto_payload, &payload)
                    .await
            }
            (
                messages::ProtocolMessageHeader::PROTOCOL_ID_SECURE_CHANNEL,
                messages::ProtocolMessageHeader::OPCODE_PASE_PAKE1,
            ) => {
                self.handle_pake1(addr, &msg_header, &proto_header, &proto_payload)
                    .await
            }
            (
                messages::ProtocolMessageHeader::PROTOCOL_ID_SECURE_CHANNEL,
                messages::ProtocolMessageHeader::OPCODE_PASE_PAKE3,
            ) => {
                self.handle_pake3(addr, &msg_header, &proto_header, &proto_payload)
                    .await
            }
            (
                messages::ProtocolMessageHeader::PROTOCOL_ID_SECURE_CHANNEL,
                messages::ProtocolMessageHeader::OPCODE_CASE_SIGMA1,
            ) => {
                self.handle_sigma1(addr, &msg_header, &proto_header, &proto_payload)
                    .await
            }
            (
                messages::ProtocolMessageHeader::PROTOCOL_ID_SECURE_CHANNEL,
                messages::ProtocolMessageHeader::OPCODE_CASE_SIGMA3,
            ) => {
                self.handle_sigma3(addr, &msg_header, &proto_header, &proto_payload)
                    .await
            }
            (
                messages::ProtocolMessageHeader::PROTOCOL_ID_SECURE_CHANNEL,
                messages::ProtocolMessageHeader::OPCODE_STATUS,
            ) => {
                self.handle_status_report(&proto_payload).await
            }
            (
                messages::ProtocolMessageHeader::PROTOCOL_ID_INTERACTION,
                messages::ProtocolMessageHeader::INTERACTION_OPCODE_INVOKE_REQ,
            ) => {
                self.handle_invoke_request(addr, &msg_header, &proto_header, &proto_payload, handler)
                    .await
            }
            (
                messages::ProtocolMessageHeader::PROTOCOL_ID_INTERACTION,
                messages::ProtocolMessageHeader::INTERACTION_OPCODE_STATUS_RESP,
            ) => {
                self.handle_status_response(addr, &msg_header, &proto_header)
                    .await
            }
            (
                messages::ProtocolMessageHeader::PROTOCOL_ID_INTERACTION,
                messages::ProtocolMessageHeader::INTERACTION_OPCODE_READ_REQ,
            ) => {
                log::debug!("Received IM read request");
                self.handle_read_request(addr, &msg_header, &proto_header, &proto_payload)
                    .await
            }
            (
                messages::ProtocolMessageHeader::PROTOCOL_ID_INTERACTION,
                messages::ProtocolMessageHeader::INTERACTION_OPCODE_SUBSCRIBE_REQ,
            ) => {
                log::debug!("Received IM subscribe request");
                self.handle_subscribe_request(addr, &msg_header, &proto_header, &proto_payload)
                    .await
            }
            (
                messages::ProtocolMessageHeader::PROTOCOL_ID_INTERACTION,
                messages::ProtocolMessageHeader::INTERACTION_OPCODE_WRITE_REQ,
            ) => {
                log::debug!("Received IM write request");
                self.handle_write_request(addr, &msg_header, &proto_header, &proto_payload)
                    .await
            }

            _ => {
                log::warn!(
                    "Unhandled opcode: protocol={} opcode=0x{:02x}",
                    proto_header.protocol_id,
                    proto_header.opcode
                );
                Ok(())
            }
        }
    }
}
