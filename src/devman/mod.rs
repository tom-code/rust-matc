//! Device manager for simplified Matter device interaction.
//!
//! Wraps certificate management, transport, controller, and a persistent device
//! registry so that commissioning and connecting to devices is simpler
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
//! # Reconnecting later
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

use crate::{certmanager, controller, transport};

pub struct DeviceManager {
    base_path: String,
    config: ManagerConfig,
    transport: Arc<transport::Transport>,
    controller: Arc<controller::Controller>,
    certmanager: Arc<dyn certmanager::CertManager>,
    registry: std::sync::Mutex<device::DeviceRegistry>,
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

        Ok(Self {
            base_path: base_path.to_owned(),
            config,
            transport,
            controller,
            certmanager: cm,
            registry: std::sync::Mutex::new(registry),
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

        Ok(Self {
            base_path: base_path.to_owned(),
            config,
            transport,
            controller,
            certmanager: cm,
            registry: std::sync::Mutex::new(registry),
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
    pub async fn connect(&self, node_id: u64) -> Result<controller::Connection> {
        let address = {
            let reg = self.registry.lock().map_err(|e| anyhow::anyhow!("registry lock: {}", e))?;
            reg.get(node_id)
                .context(format!("device {} not found in registry", node_id))?
                .address
                .clone()
        };
        let conn = self.transport.create_connection(&address).await;
        self.controller
            .auth_sigma(&conn, node_id, self.config.controller_id)
            .await
    }

    /// Connect to a previously commissioned device by friendly name.
    pub async fn connect_by_name(&self, name: &str) -> Result<controller::Connection> {
        let (node_id, address) = {
            let reg = self.registry.lock().map_err(|e| anyhow::anyhow!("registry lock: {}", e))?;
            let dev = reg
                .get_by_name(name)
                .context(format!("device '{}' not found in registry", name))?;
            (dev.node_id, dev.address.clone())
        };
        let conn = self.transport.create_connection(&address).await;
        self.controller
            .auth_sigma(&conn, node_id, self.config.controller_id)
            .await
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
