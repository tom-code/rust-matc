use crate::{fabric, sigma, spake2p};

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
}

pub(crate) struct SubscribeState {
    pub(crate) exchange_id: u16,
    pub(crate) subscription_id: u32,
}

pub(crate) struct ActiveSubscription {
    pub(crate) subscription_id: u32,
    pub(crate) session_id: u16,
    pub(crate) peer_addr: std::net::SocketAddr,
    pub(crate) max_interval_secs: u16,
}

pub(crate) struct FabricInfo {
    pub(crate) ipk: Vec<u8>,
    pub(crate) fabric: Option<fabric::Fabric>,
    pub(crate) device_matter_cert: Vec<u8>,
    pub(crate) controller_id: u64,
    #[allow(dead_code)]
    pub(crate) vendor_id: u16,
}
