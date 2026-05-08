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

use tokio::sync::mpsc::UnboundedReceiver;

use crate::{certmanager, controller, discover, fabric::Fabric, mdns2, onboarding, transport};

pub struct DeviceManager {
    base_path: String,
    config: ManagerConfig,
    transport: Arc<transport::Transport>,
    controller: Arc<controller::Controller>,
    certmanager: Arc<dyn certmanager::CertManager>,
    registry: std::sync::Mutex<device::DeviceRegistry>,
    mdns: Arc<mdns2::MdnsService>,
    mdns_receiver: tokio::sync::Mutex<UnboundedReceiver<mdns2::MdnsEvent>>,
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
        let (mdns, mdns_receiver) = mdns2::MdnsService::new().await?;

        Ok(Self {
            base_path: base_path.to_owned(),
            config,
            transport,
            controller,
            certmanager: cm,
            registry: std::sync::Mutex::new(registry),
            mdns,
            mdns_receiver: tokio::sync::Mutex::new(mdns_receiver),
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
        let (mdns, mdns_receiver) = mdns2::MdnsService::new().await?;

        Ok(Self {
            base_path: base_path.to_owned(),
            config,
            transport,
            controller,
            certmanager: cm,
            registry: std::sync::Mutex::new(registry),
            mdns,
            mdns_receiver: tokio::sync::Mutex::new(mdns_receiver),
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
        let conn = self.transport.create_connection(address).await;
        let connection = self
            .controller
            .commission(&conn, pin, node_id, self.config.controller_id)
            .await?;

        let device = Device {
            node_id,
            address: address.to_owned(),
            name: name.to_owned(),
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

    /// Try auth_sigma at the given address; on failure, re-discover via mDNS and retry once.
    async fn connect_with_rediscovery(&self, node_id: u64, address: &str) -> Result<controller::Connection> {
        let conn = self.transport.create_connection(address).await;
        match self.controller.auth_sigma(&conn, node_id, self.config.controller_id).await {
            Ok(c) => Ok(c),
            Err(e) => {
                log::info!("Connection to {} failed ({}), attempting operational rediscovery...", address, e);
                let new_address = self.discover_device(node_id, Duration::from_secs(10)).await
                    .context(format!("rediscovery for node {} after connect failure", node_id))?;
                let conn = self.transport.create_connection(&new_address).await;
                self.controller
                    .auth_sigma(&conn, node_id, self.config.controller_id)
                    .await
                    .context(format!("connection still failed after rediscovery at {}", new_address))
            }
        }
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

        let mut receiver = self.mdns_receiver.lock().await;
        self.mdns.active_lookup("_matterc._udp.local", 0xff).await;

        let discovery_timeout = Duration::from_secs(10);
        let (ips, port) = loop {
            let event = tokio::time::timeout(discovery_timeout, receiver.recv())
                .await
                .map_err(|_| anyhow::anyhow!("timed out waiting for device with discriminator {}", discriminator))?;
            match event {
                Some(mdns2::MdnsEvent::ServiceDiscovered { name: svc_name, records: _, target }) => {
                    if svc_name != "_matterc._udp.local." {
                        continue;
                    }
                    let matter_info = match discover::extract_matter_info(&target, &self.mdns).await {
                        Ok(i) => i,
                        Err(e) => {
                            log::debug!("Failed to extract Matter info from {}: {}", target, e);
                            continue;
                        }
                    };
                    if let Some(ref d) = matter_info.discriminator {
                        let mut mdns_discriminator = d.parse::<u16>()?;
                        if info.is_short_discriminator {
                            mdns_discriminator &= 0xf00;
                        }
                        if mdns_discriminator == discriminator {
                            break (matter_info.ips, matter_info.port.unwrap_or(5540));
                        }
                    }
                }
                None => {
                    anyhow::bail!("no commissionable device found with discriminator {}", discriminator);
                }
                _ => {}
            }
        };
        drop(receiver);

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
            match self.commission(&address, passcode, node_id, name).await {
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
                &self.mdns_receiver,
            )
            .await?;

        let device = crate::devman::Device {
            node_id,
            address: String::new(), // will be filled on first connect
            name: name.to_owned(),
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
        let ca_public_key = self.certmanager.get_ca_public_key()?;
        let fabric = Fabric::new(self.config.fabric_id, 0, &ca_public_key);
        let compressed = fabric.compressed().context("computing compressed fabric ID")?;
        let instance_name = format!("{}-{:016X}", hex::encode_upper(&compressed), node_id);
        let expected_target = format!("{}._matter._tcp.local.", instance_name);

        log::info!("Operational discovery for instance {}...", instance_name);

        let mut receiver = self.mdns_receiver.lock().await;
        self.mdns.active_lookup("_matter._tcp.local", 0xff).await;

        let (ips, port) = loop {
            let event = tokio::time::timeout(timeout, receiver.recv())
                .await
                .map_err(|_| anyhow::anyhow!("operational discovery timeout for node {}", node_id))?;
            match event {
                Some(mdns2::MdnsEvent::ServiceDiscovered { name: svc_name, records: _, target }) => {
                    if svc_name != "_matter._tcp.local." {
                        continue;
                    }
                    if target != expected_target {
                        continue;
                    }
                    let matter_info = match discover::extract_matter_info(&target, &self.mdns).await {
                        Ok(i) => i,
                        Err(e) => {
                            log::debug!("Failed to extract Matter info from {}: {}", target, e);
                            continue;
                        }
                    };
                    break (matter_info.ips, matter_info.port.unwrap_or(5540));
                }
                None => {
                    anyhow::bail!("no operational mDNS result for instance {}", instance_name);
                }
                _ => {}
            }
        };
        drop(receiver);

        let ip = ips.first()
            .context(format!("discovered {} but no IPs in response", instance_name))?;
        let address = if ip.is_ipv6() {
            format!("[{}]:{}", ip, port)
        } else {
            format!("{}:{}", ip, port)
        };

        self.update_device_address(node_id, &address)?;
        Ok(address)
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
