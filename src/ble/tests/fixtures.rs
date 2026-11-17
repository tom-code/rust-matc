//! Named test-device data, independent of backend failures and event ordering.

use std::collections::HashMap;

use btleplug::api::PeripheralProperties;
use uuid::Uuid;

use super::{
    backend::{CentralEvent, Device},
    MATTER_SERVICE_UUID,
};

#[derive(Clone, Debug, Default)]
pub struct TestDeviceDefinition {
    pub id: u64,
    pub discriminator: u16,
    pub advertisement_version: u8,
    pub vendor_id: u16,
    pub product_id: u16,
    pub additional_flags: u8,
    pub name: Option<String>,
    pub rssi: Option<i16>,
    pub tx_power: Option<i16>,
    pub advertised_services: Vec<Uuid>,
}

impl TestDeviceDefinition {
    /// Encode the Matter service-data payload, excluding the 0xFFF6 service UUID.
    /// Layout: <https://github.com/project-chip/connectedhomeip/blob/master/src/ble/CHIPBleServiceData.h>
    pub fn service_data(&self) -> [u8; 8] {
        assert!(
            self.discriminator <= 0x0fff,
            "discriminator must fit in 12 bits"
        );
        assert!(
            self.advertisement_version <= 0x0f,
            "advertisement version must fit in 4 bits"
        );
        let discriminator_and_version =
            self.discriminator | (u16::from(self.advertisement_version) << 12);
        let [disc_low, disc_high] = discriminator_and_version.to_le_bytes();
        let [vendor_low, vendor_high] = self.vendor_id.to_le_bytes();
        let [product_low, product_high] = self.product_id.to_le_bytes();
        [
            0x00,
            disc_low,
            disc_high,
            vendor_low,
            vendor_high,
            product_low,
            product_high,
            self.additional_flags,
        ]
    }

    pub fn properties(&self) -> PeripheralProperties {
        PeripheralProperties {
            local_name: self.name.clone(),
            rssi: self.rssi,
            tx_power_level: self.tx_power,
            services: self.advertised_services.clone(),
            service_data: HashMap::from([(MATTER_SERVICE_UUID, self.service_data().to_vec())]),
            ..Default::default()
        }
    }

    /// Build cached properties explicitly; creating an event does not populate this cache.
    pub fn device(&self) -> Device {
        Device {
            properties: Some(self.properties()),
            ..Default::default()
        }
    }

    /// Build an event independently of the peripheral's cached properties.
    pub fn advertisement(&self) -> CentralEvent {
        raw_advertisement(self.id, &self.service_data())
    }
}

/// Bypass fixture encoding for independent wire vectors and malformed payloads.
pub fn raw_advertisement(id: u64, data: &[u8]) -> CentralEvent {
    CentralEvent::ServiceDataAdvertisement {
        id,
        service_data: HashMap::from([(MATTER_SERVICE_UUID, data.to_vec())]),
    }
}

pub fn raw_device(data: &[u8]) -> Device {
    Device {
        properties: Some(PeripheralProperties {
            service_data: HashMap::from([(MATTER_SERVICE_UUID, data.to_vec())]),
            ..Default::default()
        }),
        ..Default::default()
    }
}
