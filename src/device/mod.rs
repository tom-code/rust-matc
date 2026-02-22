//! very experimental device implementation with many things hardcoded for testing and development purposes.

mod attributes;
mod case_handler;
mod commissioning;
mod crypto;
mod interaction;
mod pase;
mod send;
mod types;

pub use types::DeviceConfig;
use types::{ActiveSubscription, CaseState, FabricInfo, PaseState, SubscribeState};

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use anyhow::{Ok, Result};
use tokio::net::UdpSocket;

use crate::{messages, session};

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
    pub(crate) case_state: Option<CaseState>,
    pub(crate) case_session: Option<session::Session>,
    pub(crate) subscribe_states: Vec<SubscribeState>,
    pub(crate) active_subscriptions: Vec<ActiveSubscription>,
    // Received from controller during commissioning
    pub(crate) trusted_root_cert: Option<Vec<u8>>,
    pub(crate) noc: Option<Vec<u8>>,
    pub(crate) icac: Option<Vec<u8>>,
    pub(crate) fabric_info: Option<FabricInfo>,
    // Duplicate detection
    pub(crate) received_counters: HashSet<u32>,
    // Attribute store: (endpoint, cluster, attribute) -> pre-tagged TLV at context tag 2
    pub(crate) attributes: HashMap<(u16, u32, u32), Vec<u8>>,
    pub(crate) mdns: Arc<crate::mdns2::MdnsService>,
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
            case_state: None,
            case_session: None,
            subscribe_states: Vec::new(),
            active_subscriptions: Vec::new(),
            trusted_root_cert: None,
            noc: None,
            fabric_info: None,
            received_counters: HashSet::new(),
            attributes: HashMap::new(),
            mdns,
            icac: None,
        };
        device.setup_default_attributes()?;

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
        let svc = crate::mdns2::ServiceRegistration {
            instance_name,
            service_type: "_matterc._udp.local".to_string(),
            port,
            txt_records: vec![
                ("D".to_string(), device.config.discriminator.to_string()),
                (
                    "VP".to_string(),
                    format!("{}+{}", device.config.vendor_id, device.config.product_id),
                ),
                ("CM".to_string(), "1".to_string()),
                ("PH".to_string(), "33".to_string()),
            ],
            hostname: device.config.hostname.clone(),
            ttl: 120,
            subtypes: vec![format!("_S{}", short_disc)],
        };
        device.mdns.register_service(svc).await;

        Ok(device)
    }

    pub(crate) fn next_counter(&self) -> u32 {
        self.message_counter.fetch_add(1, Ordering::Relaxed)
    }

    pub async fn run(&mut self) -> Result<()> {
        let mut buf = [0u8; 4096];
        log::info!(
            "Device listening on {} (PIN: {})",
            self.config.listen_address,
            self.config.pin
        );
        loop {
            let keepalive_delay = self
                .active_subscriptions
                .iter()
                .map(|sub| (sub.max_interval_secs as u64) / 2)
                .min()
                .map(std::time::Duration::from_secs)
                .unwrap_or_else(|| std::time::Duration::from_secs(3600));
            tokio::select! {
                result = self.socket.recv_from(&mut buf) => {
                    let (len, addr) = result?;
                    let data = buf[..len].to_vec();
                    if let Err(e) = self.handle_packet(&data, &addr).await {
                        log::warn!("Error handling packet from {}: {:?}", addr, e);
                    }
                }
                _ = tokio::time::sleep(keepalive_delay) => {
                    if let Err(e) = self.send_subscription_report().await {
                        log::warn!("Error sending subscription keepalive: {:?}", e);
                    }
                }
            }
        }
    }

    async fn handle_packet(&mut self, data: &[u8], addr: &std::net::SocketAddr) -> Result<()> {
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
            // Encrypted message - try CASE session first, then PASE
            let session = self
                .case_session
                .as_ref()
                .filter(|s| s.my_session_id == msg_header.session_id)
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
                messages::ProtocolMessageHeader::PROTOCOL_ID_INTERACTION,
                messages::ProtocolMessageHeader::INTERACTION_OPCODE_INVOKE_REQ,
            ) => {
                self.handle_invoke_request(addr, &msg_header, &proto_header, &proto_payload)
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
