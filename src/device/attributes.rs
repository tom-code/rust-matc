use anyhow::Result;

use crate::{clusters, tlv};

use super::Device;

impl Device {
    pub(super) fn setup_default_attributes(&mut self) -> Result<()> {
        use clusters::defs::*;

        // General Commissioning cluster
        self.set_attribute_bool(
            0,
            CLUSTER_ID_GENERAL_COMMISSIONING,
            CLUSTER_GENERAL_COMMISSIONING_ATTR_ID_SUPPORTSCONCURRENTCONNECTION,
            true,
        );
        self.set_attribute_u64(
            0,
            CLUSTER_ID_GENERAL_COMMISSIONING,
            CLUSTER_GENERAL_COMMISSIONING_ATTR_ID_BREADCRUMB,
            0u64,
        );

        let mut bci_tlv = tlv::TlvBuffer::new();
        bci_tlv.write_struct(2)?;
        bci_tlv.write_uint16(0, 100)?;
        bci_tlv.write_uint16(1, 200)?;
        bci_tlv.write_struct_end()?;
        self.set_attribute_raw(
            0,
            CLUSTER_ID_GENERAL_COMMISSIONING,
            CLUSTER_GENERAL_COMMISSIONING_ATTR_ID_BASICCOMMISSIONINGINFO,
            &bci_tlv.data,
        );

        self.set_attribute_u8(
            0,
            CLUSTER_ID_GENERAL_COMMISSIONING,
            CLUSTER_GENERAL_COMMISSIONING_ATTR_ID_REGULATORYCONFIG,
            0u8,
        );
        self.set_attribute_u8(
            0,
            CLUSTER_ID_GENERAL_COMMISSIONING,
            CLUSTER_GENERAL_COMMISSIONING_ATTR_ID_LOCATIONCAPABILITY,
            0u8,
        );
        self.set_attribute_bool(
            0,
            CLUSTER_ID_GENERAL_COMMISSIONING,
            CLUSTER_GENERAL_COMMISSIONING_ATTR_ID_ISCOMMISSIONINGWITHOUTPOWER,
            false,
        );

        // Basic Information cluster
        let vendor_id = self.config.vendor_id;
        let product_id = self.config.product_id;
        self.set_attribute_u16(
            0,
            CLUSTER_ID_BASIC_INFORMATION,
            CLUSTER_BASIC_INFORMATION_ATTR_ID_VENDORID,
            vendor_id,
        );
        self.set_attribute_u16(
            0,
            CLUSTER_ID_BASIC_INFORMATION,
            CLUSTER_BASIC_INFORMATION_ATTR_ID_PRODUCTID,
            product_id,
        );

        // Network Commissioning cluster
        self.set_attribute_u8(
            0,
            CLUSTER_ID_NETWORK_COMMISSIONING,
            CLUSTER_NETWORK_COMMISSIONING_ATTR_ID_CONNECTMAXTIMESECONDS,
            120u8,
        );
        self.set_attribute_u8(
            0,
            CLUSTER_ID_OPERATIONAL_CREDENTIALS,
            CLUSTER_OPERATIONAL_CREDENTIALS_ATTR_ID_CURRENTFABRICINDEX,
            1u8,
        );

        let mut buf = tlv::TlvBuffer::new();
        buf.write_array(2)?;
        buf.write_uint16_notag(1)?;
        buf.write_struct_end()?;
        self.set_attribute_raw(
            0,
            clusters::defs::CLUSTER_ID_DESCRIPTOR,
            clusters::defs::CLUSTER_DESCRIPTOR_ATTR_ID_PARTSLIST,
            &buf.data,
        );

        let mut buf = tlv::TlvBuffer::new();
        buf.write_array(2)?;
        buf.write_anon_struct()?;
        buf.write_uint32(0, 0x100)?;
        buf.write_uint16(1, 0)?;
        buf.write_struct_end()?;
        buf.write_struct_end()?;
        self.set_attribute_raw(
            1,
            clusters::defs::CLUSTER_ID_DESCRIPTOR,
            clusters::defs::CLUSTER_DESCRIPTOR_ATTR_ID_DEVICETYPELIST,
            &buf.data,
        );

        // WiFi Network Diagnostics cluster (0x60), attr 1
        self.set_attribute_u8(0, 0x60, 1, 3u8);

        // Basic Information: SoftwareVersion and SoftwareVersionString
        self.set_attribute_u32(
            0,
            CLUSTER_ID_BASIC_INFORMATION,
            CLUSTER_BASIC_INFORMATION_ATTR_ID_SOFTWAREVERSION,
            3u32,
        );
        self.set_attribute_string(
            0,
            CLUSTER_ID_BASIC_INFORMATION,
            CLUSTER_BASIC_INFORMATION_ATTR_ID_SOFTWAREVERSIONSTRING,
            "3",
        );

        // Descriptor ServerList for endpoint 0 and 1
        let mut buf = tlv::TlvBuffer::new();
        buf.write_array(2)?;
        buf.write_uint16_notag(clusters::defs::CLUSTER_ID_DESCRIPTOR as u16)?;
        buf.write_uint16_notag(clusters::defs::CLUSTER_ID_BASIC_INFORMATION as u16)?;
        buf.write_uint16_notag(clusters::defs::CLUSTER_ID_GENERAL_COMMISSIONING as u16)?;
        buf.write_struct_end()?;
        self.set_attribute_raw(
            0,
            clusters::defs::CLUSTER_ID_DESCRIPTOR,
            clusters::defs::CLUSTER_DESCRIPTOR_ATTR_ID_SERVERLIST,
            &buf.data,
        );
        self.set_attribute_raw(
            1,
            clusters::defs::CLUSTER_ID_DESCRIPTOR,
            clusters::defs::CLUSTER_DESCRIPTOR_ATTR_ID_SERVERLIST,
            &buf.data,
        );

        Ok(())
    }

    /// Store a `bool` attribute value to return in read responses.
    pub fn set_attribute_bool(&mut self, endpoint: u16, cluster: u32, attribute: u32, value: bool) {
        let mut buf = tlv::TlvBuffer::new();
        let _ = buf.write_bool(2, value);
        self.attributes
            .insert((endpoint, cluster, attribute), buf.data);
    }

    /// Store a `u8` attribute value to return in read responses.
    pub fn set_attribute_u8(&mut self, endpoint: u16, cluster: u32, attribute: u32, value: u8) {
        let mut buf = tlv::TlvBuffer::new();
        let _ = buf.write_uint8(2, value);
        self.attributes
            .insert((endpoint, cluster, attribute), buf.data);
    }

    /// Store a `u16` attribute value to return in read responses.
    pub fn set_attribute_u16(&mut self, endpoint: u16, cluster: u32, attribute: u32, value: u16) {
        let mut buf = tlv::TlvBuffer::new();
        let _ = buf.write_uint16(2, value);
        self.attributes
            .insert((endpoint, cluster, attribute), buf.data);
    }

    /// Store a `u32` attribute value to return in read responses.
    pub fn set_attribute_u32(&mut self, endpoint: u16, cluster: u32, attribute: u32, value: u32) {
        let mut buf = tlv::TlvBuffer::new();
        let _ = buf.write_uint32(2, value);
        self.attributes
            .insert((endpoint, cluster, attribute), buf.data);
    }

    /// Store a `u64` attribute value to return in read responses.
    pub fn set_attribute_u64(&mut self, endpoint: u16, cluster: u32, attribute: u32, value: u64) {
        let mut buf = tlv::TlvBuffer::new();
        let _ = buf.write_uint64(2, value);
        self.attributes
            .insert((endpoint, cluster, attribute), buf.data);
    }

    pub fn set_attribute_string(
        &mut self,
        endpoint: u16,
        cluster: u32,
        attribute: u32,
        value: &str,
    ) {
        let mut buf = tlv::TlvBuffer::new();
        let _ = buf.write_string(2, value);
        self.attributes
            .insert((endpoint, cluster, attribute), buf.data);
    }

    pub fn set_attribute_raw(&mut self, endpoint: u16, cluster: u32, attribute: u32, value: &[u8]) {
        self.attributes
            .insert((endpoint, cluster, attribute), value.to_vec());
    }
}
