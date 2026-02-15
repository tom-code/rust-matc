use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub node_id: u64,
    pub address: String,
    pub name: String,
}

pub(crate) struct DeviceRegistry {
    path: String,
    devices: Vec<Device>,
}

impl DeviceRegistry {
    pub fn load(path: &str) -> Result<Self> {
        let devices = match std::fs::read_to_string(path) {
            Ok(data) => serde_json::from_str(&data).context("parsing devices.json")?,
            Err(_) => Vec::new(),
        };
        Ok(Self {
            path: path.to_owned(),
            devices,
        })
    }

    fn save(&self) -> Result<()> {
        let data = serde_json::to_string_pretty(&self.devices)?;
        std::fs::write(&self.path, data).context(format!("writing devices to {}", self.path))
    }

    pub fn add(&mut self, device: Device) -> Result<()> {
        // Check for duplicate name on a different node_id
        if let Some(existing) = self.devices.iter().find(|d| d.name == device.name) {
            if existing.node_id != device.node_id {
                anyhow::bail!("device name '{}' already in use by node {}", device.name, existing.node_id);
            }
        }
        // Replace if same node_id, otherwise push
        if let Some(pos) = self.devices.iter().position(|d| d.node_id == device.node_id) {
            self.devices[pos] = device;
        } else {
            self.devices.push(device);
        }
        self.save()
    }

    pub fn remove(&mut self, node_id: u64) -> Result<()> {
        self.devices.retain(|d| d.node_id != node_id);
        self.save()
    }

    pub fn get(&self, node_id: u64) -> Option<&Device> {
        self.devices.iter().find(|d| d.node_id == node_id)
    }

    pub fn get_by_name(&self, name: &str) -> Option<&Device> {
        self.devices.iter().find(|d| d.name == name)
    }

    pub fn list(&self) -> &[Device] {
        &self.devices
    }

    pub fn update_address(&mut self, node_id: u64, address: &str) -> Result<()> {
        let dev = self.devices.iter_mut().find(|d| d.node_id == node_id)
            .context(format!("device {} not found", node_id))?;
        dev.address = address.to_owned();
        self.save()
    }

    pub fn rename(&mut self, node_id: u64, name: &str) -> Result<()> {
        // Check for duplicate name
        if let Some(existing) = self.devices.iter().find(|d| d.name == name) {
            if existing.node_id != node_id {
                anyhow::bail!("device name '{}' already in use by node {}", name, existing.node_id);
            }
        }
        let dev = self.devices.iter_mut().find(|d| d.node_id == node_id)
            .context(format!("device {} not found", node_id))?;
        dev.name = name.to_owned();
        self.save()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_path(name: &str) -> String {
        let dir = std::env::temp_dir().join(format!("matc_test_{}", name));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        println!("Using test directory: {:?}", dir);
        dir.join("devices.json").to_str().unwrap().to_owned()
    }

    #[test]
    fn registry_round_trip() {
        let path = test_path("reg_rt");

        let mut reg = DeviceRegistry::load(&path).unwrap();
        assert!(reg.list().is_empty());

        reg.add(Device { node_id: 1, address: "1.2.3.4:5540".into(), name: "light".into() }).unwrap();
        reg.add(Device { node_id: 2, address: "1.2.3.5:5540".into(), name: "switch".into() }).unwrap();
        assert_eq!(reg.list().len(), 2);

        // reload from disk
        let reg2 = DeviceRegistry::load(&path).unwrap();
        assert_eq!(reg2.list().len(), 2);
        assert_eq!(reg2.get(1).unwrap().name, "light");
        assert_eq!(reg2.get_by_name("switch").unwrap().node_id, 2);
    }

    #[test]
    fn registry_replace_by_node_id() {
        let path = test_path("reg_replace");

        let mut reg = DeviceRegistry::load(&path).unwrap();
        reg.add(Device { node_id: 1, address: "1.2.3.4:5540".into(), name: "light".into() }).unwrap();
        reg.add(Device { node_id: 1, address: "1.2.3.5:5540".into(), name: "light2".into() }).unwrap();
        assert_eq!(reg.list().len(), 1);
        assert_eq!(reg.get(1).unwrap().name, "light2");
    }

    #[test]
    fn registry_unique_names() {
        let path = test_path("reg_unique");

        let mut reg = DeviceRegistry::load(&path).unwrap();
        reg.add(Device { node_id: 1, address: "1.2.3.4:5540".into(), name: "light".into() }).unwrap();
        let err = reg.add(Device { node_id: 2, address: "1.2.3.5:5540".into(), name: "light".into() });
        assert!(err.is_err());
    }

    #[test]
    fn registry_rename_and_update_address() {
        let path = test_path("reg_rename");

        let mut reg = DeviceRegistry::load(&path).unwrap();
        reg.add(Device { node_id: 1, address: "1.2.3.4:5540".into(), name: "light".into() }).unwrap();
        reg.rename(1, "kitchen light").unwrap();
        assert_eq!(reg.get(1).unwrap().name, "kitchen light");

        reg.update_address(1, "10.0.0.1:5540").unwrap();
        assert_eq!(reg.get(1).unwrap().address, "10.0.0.1:5540");
    }

    #[test]
    fn registry_remove() {
        let path = test_path("reg_remove");

        let mut reg = DeviceRegistry::load(&path).unwrap();
        reg.add(Device { node_id: 1, address: "1.2.3.4:5540".into(), name: "light".into() }).unwrap();
        reg.remove(1).unwrap();
        assert!(reg.list().is_empty());
    }
}
