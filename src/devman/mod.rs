//! Device manager for simplified Matter device interaction.
//!
//! Wraps certificate management, transport, controller, mDNS discovery, and a persistent device
//! registry so that commissioning and connecting to devices is simpler.
//!
//! # Features
//!
//! - **Commission by address**: [`DeviceManager::commission`] when the device IP is known
//! - **Commission by pairing code**: [`DeviceManager::commission_with_code`] decodes a manual
//!   pairing code, discovers the device via commissionable mDNS (`_matterc._udp.local`),
//!   and commissions it automatically
//! - **Connect with auto-rediscovery**: [`DeviceManager::connect`] and
//!   [`DeviceManager::connect_by_name`] try the stored address first; if the connection fails
//!   (e.g. device changed IP), they automatically re-discover the device via operational mDNS
//!   (`_matter._tcp.local`) and retry
//! - **Explicit discovery**: [`DeviceManager::discover_device`] finds the current address of a
//!   commissioned device via operational mDNS and updates the registry
//!
//! # First-time setup
//! ```no_run
//! # use matc::devman::{DeviceManager, ManagerConfig};
//! # #[tokio::main]
//! # async fn main() -> anyhow::Result<()> {
//! let config = ManagerConfig { fabric_id: 1000, controller_id: 100,
//!                              local_address: "0.0.0.0:5555".into() };
//! let dm = DeviceManager::create("./matter-data", config).await?;
//! let conn = dm.commission("192.168.1.100:5540", 123456, 300, "kitchen light").await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Commission using manual pairing code
//! ```no_run
//! # use matc::devman::DeviceManager;
//! # #[tokio::main]
//! # async fn main() -> anyhow::Result<()> {
//! let dm = DeviceManager::load("./matter-data").await?;
//! let conn = dm.commission_with_code("0251-520-0076", 300, "kitchen light").await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Reconnecting later
//!
//! If the device changed its IP address since commissioning, the connection automatically
//! falls back to operational mDNS discovery, updates the stored address, and retries.
//! ```no_run
//! # use matc::devman::DeviceManager;
//! # #[tokio::main]
//! # async fn main() -> anyhow::Result<()> {
//! let dm = DeviceManager::load("./matter-data").await?;
//! let conn = dm.connect_by_name("kitchen light").await?;
//! # Ok(())
//! # }
//! ```

mod config;
mod device;

pub use config::ManagerConfig;
pub use device::Device;

use std::sync::Arc;

use anyhow::{Context, Result};

use std::time::Duration;

use crate::{certmanager, controller, discover::{self, MatterDeviceInfo}, fabric::Fabric, mdns2, onboarding, transport};

pub struct DeviceManager {
    base_path: String,
    config: ManagerConfig,
    transport: Arc<transport::Transport>,
    controller: Arc<controller::Controller>,
    certmanager: Arc<dyn certmanager::CertManager>,
    registry: std::sync::Mutex<device::DeviceRegistry>,
    mdns: Arc<mdns2::MdnsService>,
}

impl DeviceManager {
    /// First-time setup: creates directory structure, bootstraps CA,
    /// creates controller user, and saves config.
    pub async fn create(base_path: &str, config: ManagerConfig) -> Result<Self> {
        std::fs::create_dir_all(base_path)
            .context(format!("creating base directory {}", base_path))?;
        config::save_config(base_path, &config)?;

        let pem = config::pem_path(base_path);
        let cm = certmanager::FileCertManager::new(config.fabric_id, &pem);
        cm.bootstrap()?;
        cm.create_user(config.controller_id)?;

        let cm: Arc<dyn certmanager::CertManager> = certmanager::FileCertManager::load(&pem)?;
        let transport = transport::Transport::new(&config.local_address).await?;
        let controller = controller::Controller::new(&cm, &transport, config.fabric_id)?;
        let registry = device::DeviceRegistry::load(&config::devices_path(base_path))?;
        let mdns = mdns2::MdnsService::new().await?;

        Ok(Self {
            base_path: base_path.to_owned(),
            config,
            transport,
            controller,
            certmanager: cm,
            registry: std::sync::Mutex::new(registry),
            mdns,
        })
    }

    /// Load an existing device manager from a previously created base directory.
    pub async fn load(base_path: &str) -> Result<Self> {
        let config = config::load_config(base_path)?;
        let pem = config::pem_path(base_path);
        let cm: Arc<dyn certmanager::CertManager> = certmanager::FileCertManager::load(&pem)?;
        let transport = transport::Transport::new(&config.local_address).await?;
        let controller = controller::Controller::new(&cm, &transport, config.fabric_id)?;
        let registry = device::DeviceRegistry::load(&config::devices_path(base_path))?;
        let mdns = mdns2::MdnsService::new().await?;

        Ok(Self {
            base_path: base_path.to_owned(),
            config,
            transport,
            controller,
            certmanager: cm,
            registry: std::sync::Mutex::new(registry),
            mdns,
        })
    }

    /// Commission a device and save it to the registry.
    /// Returns an authenticated connection ready for commands.
    pub async fn commission(
        &self,
        address: &str,
        pin: u32,
        node_id: u64,
        name: &str,
    ) -> Result<controller::Connection> {
        self.commission_at(address, pin, node_id, name, (None, None, None)).await
    }

    /// Commission at a known address with optional advertised MRP intervals
    /// (SII/SAI/SAT milliseconds), which are applied to the connection and
    /// persisted in the registry.
    async fn commission_at(
        &self,
        address: &str,
        pin: u32,
        node_id: u64,
        name: &str,
        mrp_ms: (Option<u32>, Option<u32>, Option<u32>),
    ) -> Result<controller::Connection> {
        let conn = self.transport.create_connection(address).await;
        conn.set_mrp_params(crate::mrp::MrpParameters::from_txt_ms(mrp_ms.0, mrp_ms.1, mrp_ms.2));
        let connection = self
            .controller
            .commission(&conn, pin, node_id, self.config.controller_id)
            .await?;

        let device = Device {
            node_id,
            address: address.to_owned(),
            name: name.to_owned(),
            sii_ms: mrp_ms.0,
            sai_ms: mrp_ms.1,
            sat_ms: mrp_ms.2,
        };
        self.registry
            .lock()
            .map_err(|e| anyhow::anyhow!("registry lock: {}", e))?
            .add(device)?;

        Ok(connection)
    }

    /// Connect to a previously commissioned device by node ID.
    /// If the stored address fails, automatically re-discovers the device via operational mDNS.
    pub async fn connect(&self, node_id: u64) -> Result<controller::Connection> {
        let address = {
            let reg = self.registry.lock().map_err(|e| anyhow::anyhow!("registry lock: {}", e))?;
            reg.get(node_id)
                .context(format!("device {} not found in registry", node_id))?
                .address
                .clone()
        };
        self.connect_with_rediscovery(node_id, &address).await
    }

    /// Connect to a previously commissioned device by friendly name.
    /// If the stored address fails, automatically re-discovers the device via operational mDNS.
    pub async fn connect_by_name(&self, name: &str) -> Result<controller::Connection> {
        let (node_id, address) = {
            let reg = self.registry.lock().map_err(|e| anyhow::anyhow!("registry lock: {}", e))?;
            let dev = reg
                .get_by_name(name)
                .context(format!("device '{}' not found in registry", name))?;
            (dev.node_id, dev.address.clone())
        };
        self.connect_with_rediscovery(node_id, &address).await
    }

    /// Connect with BUSY retry and one round of mDNS rediscovery on non-BUSY failure.
    /// BUSY handling is delegated to Controller::auth_sigma_with_busy_retry so that
    /// in-place reauth uses identical retry semantics.
    async fn connect_with_rediscovery(&self, node_id: u64, address: &str) -> Result<controller::Connection> {
        let stored_mrp = self
            .registry
            .lock()
            .map_err(|e| anyhow::anyhow!("registry lock: {}", e))?
            .get(node_id)
            .map(|d| d.mrp_params())
            .unwrap_or_default();
        let mut current_address = address.to_string();
        // Create connection once and reuse across retries; only replace if address changes.
        let mut conn = self.transport.create_connection(&current_address).await;
        conn.set_mrp_params(stored_mrp);

        match self.controller.auth_sigma_with_busy_retry(&conn, node_id, self.config.controller_id).await {
            Ok(ses) => Ok(controller::Connection::from_parts(conn, ses)),
            Err(e) => {
                // Try operational mDNS rediscovery once, then one more attempt.
                log::info!(
                    "Connection to {} failed ({}), attempting operational rediscovery...",
                    current_address, e
                );
                let (new_address, matter_info) = self
                    .discover_device_info(node_id, Duration::from_secs(10))
                    .await
                    .context(format!("rediscovery for node {} after connect failure", node_id))?;
                current_address = new_address;
                conn = self.transport.create_connection(&current_address).await;
                conn.set_mrp_params(matter_info.mrp_params());
                let ses = self
                    .controller
                    .auth_sigma_with_busy_retry(&conn, node_id, self.config.controller_id)
                    .await
                    .context(format!(
                        "connection still failed after rediscovery at {}", current_address
                    ))?;
                Ok(controller::Connection::from_parts(conn, ses))
            }
        }
    }

    /// Re-run CASE on an existing controller::Connection without tearing down the
    /// transport channel. Delegates to Connection::reauth which pauses the read loop,
    /// calls auth_sigma_with_busy_retry, swaps the session, and restarts the loop.
    pub async fn reauth(&self, conn: &controller::Connection, node_id: u64) -> Result<()> {
        conn.reauth(&self.controller, node_id, self.config.controller_id).await
    }

    /// Commission a device using a manual pairing code.
    /// Decodes the pairing code to extract the discriminator, discovers the device via
    /// commissionable mDNS, then commissions it. Returns an authenticated connection.
    pub async fn commission_with_code(
        &self,
        pairing_code: &str,
        node_id: u64,
        name: &str,
    ) -> Result<controller::Connection> {
        let info = onboarding::decode_manual_pairing_code(pairing_code)
            .context("decoding manual pairing code")?;
        let discriminator = info.discriminator;
        let passcode = info.passcode;

        log::info!("Discovering device with discriminator {}...", discriminator);

        let is_short = info.is_short_discriminator;
        let (_, matter_info) = discover::discover_one(
            &self.mdns,
            "_matterc._udp.local",
            "_matterc._udp.local.",
            Duration::from_secs(10),
            move |_, i| {
                if let Some(ref d) = i.discriminator {
                    if let Ok(mut disc) = d.parse::<u16>() {
                        if is_short { disc &= 0xf00; }
                        return disc == discriminator;
                    }
                }
                false
            },
        ).await.context(format!("discovering device with discriminator {}", discriminator))?;

        let mrp_ms = (
            matter_info.session_idle_interval_ms,
            matter_info.session_active_interval_ms,
            matter_info.session_active_threshold_ms,
        );
        let ips = matter_info.ips;
        let port = matter_info.port.unwrap_or(5540);

        if ips.is_empty() {
            anyhow::bail!("discovered device with discriminator {} but no IPs returned", discriminator);
        }

        let mut last_err = anyhow::anyhow!("no IPs to try");
        for ip in &ips {
            let address = if ip.is_ipv6() {
                format!("[{}]:{}", ip, port)
            } else {
                format!("{}:{}", ip, port)
            };
            match self.commission_at(&address, passcode, node_id, name, mrp_ms).await {
                Ok(conn) => return Ok(conn),
                Err(e) => {
                    log::debug!("Commission attempt at {} failed: {}", address, e);
                    last_err = e;
                }
            }
        }
        Err(last_err).context(format!("commissioning failed on all IPs for discriminator {}", discriminator))
    }

    /// Commission a device that is currently advertising over BLE.
    ///
    /// Accepts either a manual pairing code (`"0251-520-0076"`) or a QR payload
    /// (`"MT:..."`). Scans for the matching BLE device, runs PASE + commissioning
    /// over BTP, optionally provisions network credentials, then completes over
    /// UDP+CASE once the device is reachable on the IP network.
    ///
    /// Requires the `ble` Cargo feature.
    #[cfg(feature = "ble")]
    pub async fn commission_ble_with_code(
        &self,
        pairing_code: &str,
        node_id: u64,
        name: &str,
        network_creds: crate::commission::NetworkCreds,
    ) -> Result<controller::Connection> {
        let info = if pairing_code.starts_with("MT:") || pairing_code.starts_with("mt:") {
            crate::onboarding::decode_qr_payload(pairing_code)
        } else {
            crate::onboarding::decode_manual_pairing_code(pairing_code)
        }
        .context("decoding pairing code")?;

        let connection = self
            .controller
            .commission_ble(
                info.discriminator,
                info.is_short_discriminator,
                info.passcode,
                node_id,
                self.config.controller_id,
                network_creds,
                &self.mdns,
            )
            .await?;

        let device = crate::devman::Device {
            node_id,
            address: String::new(), // will be filled on first connect
            name: name.to_owned(),
            ..Default::default()
        };
        self.registry
            .lock()
            .map_err(|e| anyhow::anyhow!("registry lock: {}", e))?
            .add(device)?;

        Ok(connection)
    }

    /// Discover the current address of a commissioned device via operational mDNS.
    /// Returns as soon as the device is found (no fixed timeout wait).
    /// Updates the stored address in the registry and returns the new address.
    pub async fn discover_device(&self, node_id: u64, timeout: Duration) -> Result<String> {
        let (address, _) = self.discover_device_info(node_id, timeout).await?;
        Ok(address)
    }

    /// Operational discovery returning the full mDNS info. Updates the stored
    /// address and advertised MRP intervals in the registry.
    async fn discover_device_info(
        &self,
        node_id: u64,
        timeout: Duration,
    ) -> Result<(String, MatterDeviceInfo)> {
        let ca_public_key = self.certmanager.get_ca_public_key()?;
        let fabric = Fabric::new(self.config.fabric_id, 0, &ca_public_key, &self.certmanager.get_ipk_epoch_key());
        let compressed = fabric.compressed().context("computing compressed fabric ID")?;
        let instance_name = format!("{}-{:016X}", hex::encode_upper(&compressed), node_id);
        let expected_target = format!("{}._matter._tcp.local.", instance_name);

        log::info!("Operational discovery for instance {}...", instance_name);

        let (_, matter_info) = discover::discover_one(
            &self.mdns,
            "_matter._tcp.local",
            "_matter._tcp.local.",
            timeout,
            move |target, _| target == expected_target,
        ).await.context(format!("operational discovery for node {}", node_id))?;

        let ip = matter_info.ips.first()
            .context(format!("discovered {} but no IPs in response", instance_name))?;
        let port = matter_info.port.unwrap_or(5540);
        let address = if ip.is_ipv6() {
            format!("[{}]:{}", ip, port)
        } else {
            format!("{}:{}", ip, port)
        };

        self.update_device_address(node_id, &address)?;
        if let Err(e) = self.registry
            .lock()
            .map_err(|e| anyhow::anyhow!("registry lock: {}", e))?
            .update_mrp(
                node_id,
                matter_info.session_idle_interval_ms,
                matter_info.session_active_interval_ms,
                matter_info.session_active_threshold_ms,
            )
        {
            log::debug!("failed to persist MRP intervals for node {}: {}", node_id, e);
        }
        Ok((address, matter_info))
    }

    pub async fn discover_commissionable_devices(&self, timeout: Duration) -> Result<Vec<(String, MatterDeviceInfo)>> {
        discover::discover_all(
            &self.mdns,
            "_matterc._udp.local",
            "_matterc._udp.local.",
            timeout,
        ).await
    }

    /// List all registered devices.
    pub fn list_devices(&self) -> Result<Vec<Device>> {
        let reg = self.registry.lock().map_err(|e| anyhow::anyhow!("registry lock: {}", e))?;
        Ok(reg.list().to_vec())
    }

    /// Get a device by node ID.
    pub fn get_device(&self, node_id: u64) -> Result<Option<Device>> {
        let reg = self.registry.lock().map_err(|e| anyhow::anyhow!("registry lock: {}", e))?;
        Ok(reg.get(node_id).cloned())
    }

    /// Get a device by friendly name.
    pub fn get_device_by_name(&self, name: &str) -> Result<Option<Device>> {
        let reg = self.registry.lock().map_err(|e| anyhow::anyhow!("registry lock: {}", e))?;
        Ok(reg.get_by_name(name).cloned())
    }

    /// Remove a device from the registry.
    pub fn remove_device(&self, node_id: u64) -> Result<()> {
        self.registry
            .lock()
            .map_err(|e| anyhow::anyhow!("registry lock: {}", e))?
            .remove(node_id)
    }

    /// Rename a device in the registry.
    pub fn rename_device(&self, node_id: u64, name: &str) -> Result<()> {
        self.registry
            .lock()
            .map_err(|e| anyhow::anyhow!("registry lock: {}", e))?
            .rename(node_id, name)
    }

    /// Update the stored address for a device.
    pub fn update_device_address(&self, node_id: u64, address: &str) -> Result<()> {
        self.registry
            .lock()
            .map_err(|e| anyhow::anyhow!("registry lock: {}", e))?
            .update_address(node_id, address)
    }

    /// Get a reference to the shared mDNS service.
    pub fn mdns(&self) -> &Arc<mdns2::MdnsService> {
        &self.mdns
    }

    /// Get a reference to the underlying controller.
    pub fn controller(&self) -> &Arc<controller::Controller> {
        &self.controller
    }

    /// Get a reference to the underlying transport.
    pub fn transport(&self) -> &Arc<transport::Transport> {
        &self.transport
    }

    /// Get a reference to the certificate manager.
    pub fn certmanager(&self) -> &Arc<dyn certmanager::CertManager> {
        &self.certmanager
    }

    /// Get the config.
    pub fn config(&self) -> &ManagerConfig {
        &self.config
    }

    /// Get the base path.
    pub fn base_path(&self) -> &str {
        &self.base_path
    }
}
