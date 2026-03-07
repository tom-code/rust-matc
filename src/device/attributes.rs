use anyhow::Result;

use crate::{clusters, tlv};

use super::Device;

// Global attribute IDs (Matter spec section 7.13)
const ATTR_GENERATED_CMD_LIST: u32 = 0xFFF8;
const ATTR_ACCEPTED_CMD_LIST: u32 = 0xFFF9;
const ATTR_EVENT_LIST: u32 = 0xFFFA;
const ATTR_ATTRIBUTE_LIST: u32 = 0xFFFB;
const ATTR_FEATURE_MAP: u32 = 0xFFFC;
const ATTR_CLUSTER_REVISION: u32 = 0xFFFD;

impl Device {
    pub(super) fn setup_default_attributes(&mut self) -> Result<()> {
        use clusters::defs::*;


        let mut buf = tlv::TlvBuffer::new();
        buf.write_array(2)?;
        buf.write_anon_struct()?;
        buf.write_uint32(0, 0x0016)?; // DeviceType = Root Node
        buf.write_uint16(1, 2)?; // Revision = 2
        buf.write_struct_end()?;
        buf.write_struct_end()?;
        self.set_attribute_raw(
            0,
            CLUSTER_ID_DESCRIPTOR,
            CLUSTER_DESCRIPTOR_ATTR_ID_DEVICETYPELIST,
            &buf.data,
        );

        let mut buf = tlv::TlvBuffer::new();
        buf.write_array(2)?;
        buf.write_uint32_notag(CLUSTER_ID_DESCRIPTOR)?;
        buf.write_uint32_notag(CLUSTER_ID_ACCESS_CONTROL)?;
        buf.write_uint32_notag(CLUSTER_ID_BASIC_INFORMATION)?;
        buf.write_uint32_notag(CLUSTER_ID_GENERAL_COMMISSIONING)?;
        buf.write_uint32_notag(CLUSTER_ID_NETWORK_COMMISSIONING)?;
        buf.write_uint32_notag(CLUSTER_ID_ADMINISTRATOR_COMMISSIONING)?;
        buf.write_uint32_notag(CLUSTER_ID_OPERATIONAL_CREDENTIALS)?;
        buf.write_struct_end()?;
        self.set_attribute_raw(
            0,
            CLUSTER_ID_DESCRIPTOR,
            CLUSTER_DESCRIPTOR_ATTR_ID_SERVERLIST,
            &buf.data,
        );

        self.set_empty_array(0, CLUSTER_ID_DESCRIPTOR, CLUSTER_DESCRIPTOR_ATTR_ID_CLIENTLIST);

        self.set_empty_array(0, CLUSTER_ID_DESCRIPTOR, CLUSTER_DESCRIPTOR_ATTR_ID_PARTSLIST);

        self.set_cluster_globals(
            0,
            CLUSTER_ID_DESCRIPTOR,
            3,
            0,
            &[
                CLUSTER_DESCRIPTOR_ATTR_ID_DEVICETYPELIST,
                CLUSTER_DESCRIPTOR_ATTR_ID_SERVERLIST,
                CLUSTER_DESCRIPTOR_ATTR_ID_CLIENTLIST,
                CLUSTER_DESCRIPTOR_ATTR_ID_PARTSLIST,
            ],
            &[],
            &[],
        )?;

        let vendor_id = self.config.vendor_id;
        let product_id = self.config.product_id;
        self.set_attribute_u16(
            0,
            CLUSTER_ID_BASIC_INFORMATION,
            CLUSTER_BASIC_INFORMATION_ATTR_ID_DATAMODELREVISION,
            1,
        );
        let vendor_name = self.config.vendor_name.clone();
        self.set_attribute_string(
            0,
            CLUSTER_ID_BASIC_INFORMATION,
            CLUSTER_BASIC_INFORMATION_ATTR_ID_VENDORNAME,
            &vendor_name,
        );
        self.set_attribute_u16(
            0,
            CLUSTER_ID_BASIC_INFORMATION,
            CLUSTER_BASIC_INFORMATION_ATTR_ID_VENDORID,
            vendor_id,
        );
        let product_name = self.config.product_name.clone();
        self.set_attribute_string(
            0,
            CLUSTER_ID_BASIC_INFORMATION,
            CLUSTER_BASIC_INFORMATION_ATTR_ID_PRODUCTNAME,
            &product_name,
        );
        self.set_attribute_u16(
            0,
            CLUSTER_ID_BASIC_INFORMATION,
            CLUSTER_BASIC_INFORMATION_ATTR_ID_PRODUCTID,
            product_id,
        );
        let node_label = self.config.product_name.clone();
        self.set_attribute_string(
            0,
            CLUSTER_ID_BASIC_INFORMATION,
            CLUSTER_BASIC_INFORMATION_ATTR_ID_NODELABEL,
            &node_label,
        );
        self.set_attribute_string(
            0,
            CLUSTER_ID_BASIC_INFORMATION,
            CLUSTER_BASIC_INFORMATION_ATTR_ID_LOCATION,
            "XX",
        );
        let hardware_version = self.config.hardware_version;
        self.set_attribute_u16(
            0,
            CLUSTER_ID_BASIC_INFORMATION,
            CLUSTER_BASIC_INFORMATION_ATTR_ID_HARDWAREVERSION,
            hardware_version,
        );
        let hardware_version_string = format!("{}.0", hardware_version);
        self.set_attribute_string(
            0,
            CLUSTER_ID_BASIC_INFORMATION,
            CLUSTER_BASIC_INFORMATION_ATTR_ID_HARDWAREVERSIONSTRING,
            &hardware_version_string,
        );
        let software_version = self.config.software_version;
        self.set_attribute_u32(
            0,
            CLUSTER_ID_BASIC_INFORMATION,
            CLUSTER_BASIC_INFORMATION_ATTR_ID_SOFTWAREVERSION,
            software_version,
        );
        let software_version_string = software_version.to_string();
        self.set_attribute_string(
            0,
            CLUSTER_ID_BASIC_INFORMATION,
            CLUSTER_BASIC_INFORMATION_ATTR_ID_SOFTWAREVERSIONSTRING,
            &software_version_string,
        );
        let serial_number = self.config.serial_number.clone();
        self.set_attribute_string(
            0,
            CLUSTER_ID_BASIC_INFORMATION,
            CLUSTER_BASIC_INFORMATION_ATTR_ID_SERIALNUMBER,
            &serial_number,
        );
        self.set_attribute_bool(
            0,
            CLUSTER_ID_BASIC_INFORMATION,
            CLUSTER_BASIC_INFORMATION_ATTR_ID_LOCALCONFIGDISABLED,
            false,
        );
        self.set_attribute_bool(
            0,
            CLUSTER_ID_BASIC_INFORMATION,
            CLUSTER_BASIC_INFORMATION_ATTR_ID_REACHABLE,
            true,
        );
        let unique_id = self.config.unique_id.clone();
        self.set_attribute_string(
            0,
            CLUSTER_ID_BASIC_INFORMATION,
            CLUSTER_BASIC_INFORMATION_ATTR_ID_UNIQUEID,
            &unique_id,
        );

        let mut buf = tlv::TlvBuffer::new();
        buf.write_struct(2)?;
        buf.write_uint16(0, 3)?; // CaseSessionsPerFabric
        buf.write_uint16(1, 3)?; // SubscriptionsPerFabric
        buf.write_struct_end()?;
        self.set_attribute_raw(
            0,
            CLUSTER_ID_BASIC_INFORMATION,
            CLUSTER_BASIC_INFORMATION_ATTR_ID_CAPABILITYMINIMA,
            &buf.data,
        );

        self.set_attribute_u32(
            0,
            CLUSTER_ID_BASIC_INFORMATION,
            CLUSTER_BASIC_INFORMATION_ATTR_ID_SPECIFICATIONVERSION,
            0x01030000, // Matter 1.3
        );
        self.set_attribute_u16(
            0,
            CLUSTER_ID_BASIC_INFORMATION,
            CLUSTER_BASIC_INFORMATION_ATTR_ID_MAXPATHSPERINVOKE,
            1,
        );

        self.set_cluster_globals(
            0,
            CLUSTER_ID_BASIC_INFORMATION,
            4,
            0,
            &[
                CLUSTER_BASIC_INFORMATION_ATTR_ID_DATAMODELREVISION,
                CLUSTER_BASIC_INFORMATION_ATTR_ID_VENDORNAME,
                CLUSTER_BASIC_INFORMATION_ATTR_ID_VENDORID,
                CLUSTER_BASIC_INFORMATION_ATTR_ID_PRODUCTNAME,
                CLUSTER_BASIC_INFORMATION_ATTR_ID_PRODUCTID,
                CLUSTER_BASIC_INFORMATION_ATTR_ID_NODELABEL,
                CLUSTER_BASIC_INFORMATION_ATTR_ID_LOCATION,
                CLUSTER_BASIC_INFORMATION_ATTR_ID_HARDWAREVERSION,
                CLUSTER_BASIC_INFORMATION_ATTR_ID_HARDWAREVERSIONSTRING,
                CLUSTER_BASIC_INFORMATION_ATTR_ID_SOFTWAREVERSION,
                CLUSTER_BASIC_INFORMATION_ATTR_ID_SOFTWAREVERSIONSTRING,
                CLUSTER_BASIC_INFORMATION_ATTR_ID_SERIALNUMBER,
                CLUSTER_BASIC_INFORMATION_ATTR_ID_LOCALCONFIGDISABLED,
                CLUSTER_BASIC_INFORMATION_ATTR_ID_REACHABLE,
                CLUSTER_BASIC_INFORMATION_ATTR_ID_UNIQUEID,
                CLUSTER_BASIC_INFORMATION_ATTR_ID_CAPABILITYMINIMA,
                CLUSTER_BASIC_INFORMATION_ATTR_ID_SPECIFICATIONVERSION,
                CLUSTER_BASIC_INFORMATION_ATTR_ID_MAXPATHSPERINVOKE,
            ],
            &[],
            &[],
        )?;

        self.set_attribute_u64(
            0,
            CLUSTER_ID_GENERAL_COMMISSIONING,
            CLUSTER_GENERAL_COMMISSIONING_ATTR_ID_BREADCRUMB,
            0,
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
            0,
        );
        self.set_attribute_u8(
            0,
            CLUSTER_ID_GENERAL_COMMISSIONING,
            CLUSTER_GENERAL_COMMISSIONING_ATTR_ID_LOCATIONCAPABILITY,
            0,
        );
        self.set_attribute_bool(
            0,
            CLUSTER_ID_GENERAL_COMMISSIONING,
            CLUSTER_GENERAL_COMMISSIONING_ATTR_ID_SUPPORTSCONCURRENTCONNECTION,
            true,
        );
        self.set_attribute_bool(
            0,
            CLUSTER_ID_GENERAL_COMMISSIONING,
            CLUSTER_GENERAL_COMMISSIONING_ATTR_ID_ISCOMMISSIONINGWITHOUTPOWER,
            false,
        );

        self.set_cluster_globals(
            0,
            CLUSTER_ID_GENERAL_COMMISSIONING,
            1,
            0,
            &[
                CLUSTER_GENERAL_COMMISSIONING_ATTR_ID_BREADCRUMB,
                CLUSTER_GENERAL_COMMISSIONING_ATTR_ID_BASICCOMMISSIONINGINFO,
                CLUSTER_GENERAL_COMMISSIONING_ATTR_ID_REGULATORYCONFIG,
                CLUSTER_GENERAL_COMMISSIONING_ATTR_ID_LOCATIONCAPABILITY,
                CLUSTER_GENERAL_COMMISSIONING_ATTR_ID_SUPPORTSCONCURRENTCONNECTION,
                CLUSTER_GENERAL_COMMISSIONING_ATTR_ID_ISCOMMISSIONINGWITHOUTPOWER,
            ],
            &[
                CLUSTER_GENERAL_COMMISSIONING_CMD_ID_ARMFAILSAFE,
                CLUSTER_GENERAL_COMMISSIONING_CMD_ID_SETREGULATORYCONFIG,
                CLUSTER_GENERAL_COMMISSIONING_CMD_ID_COMMISSIONINGCOMPLETE,
            ],
            &[
                CLUSTER_GENERAL_COMMISSIONING_CMD_ID_ARMFAILSAFERESPONSE,
                CLUSTER_GENERAL_COMMISSIONING_CMD_ID_SETREGULATORYCONFIGRESPONSE,
                CLUSTER_GENERAL_COMMISSIONING_CMD_ID_COMMISSIONINGCOMPLETERESPONSE,
            ],
        )?;

        self.set_attribute_u8(
            0,
            CLUSTER_ID_OPERATIONAL_CREDENTIALS,
            CLUSTER_OPERATIONAL_CREDENTIALS_ATTR_ID_SUPPORTEDFABRICS,
            8,
        );
        self.set_attribute_u8(
            0,
            CLUSTER_ID_OPERATIONAL_CREDENTIALS,
            CLUSTER_OPERATIONAL_CREDENTIALS_ATTR_ID_COMMISSIONEDFABRICS,
            1,
        );
        self.set_empty_array(
            0,
            CLUSTER_ID_OPERATIONAL_CREDENTIALS,
            CLUSTER_OPERATIONAL_CREDENTIALS_ATTR_ID_FABRICS,
        );

        self.set_cluster_globals(
            0,
            CLUSTER_ID_OPERATIONAL_CREDENTIALS,
            1,
            0,
            &[
                CLUSTER_OPERATIONAL_CREDENTIALS_ATTR_ID_NOCS,
                CLUSTER_OPERATIONAL_CREDENTIALS_ATTR_ID_FABRICS,
                CLUSTER_OPERATIONAL_CREDENTIALS_ATTR_ID_SUPPORTEDFABRICS,
                CLUSTER_OPERATIONAL_CREDENTIALS_ATTR_ID_COMMISSIONEDFABRICS,
                CLUSTER_OPERATIONAL_CREDENTIALS_ATTR_ID_TRUSTEDROOTCERTIFICATES,
                CLUSTER_OPERATIONAL_CREDENTIALS_ATTR_ID_CURRENTFABRICINDEX,
            ],
            &[
                CLUSTER_OPERATIONAL_CREDENTIALS_CMD_ID_ATTESTATIONREQUEST,
                CLUSTER_OPERATIONAL_CREDENTIALS_CMD_ID_CERTIFICATECHAINREQUEST,
                CLUSTER_OPERATIONAL_CREDENTIALS_CMD_ID_CSRREQUEST,
                CLUSTER_OPERATIONAL_CREDENTIALS_CMD_ID_ADDTRUSTEDROOTCERTIFICATE,
                CLUSTER_OPERATIONAL_CREDENTIALS_CMD_ID_ADDNOC,
                CLUSTER_OPERATIONAL_CREDENTIALS_CMD_ID_REMOVEFABRIC,
            ],
            &[
                CLUSTER_OPERATIONAL_CREDENTIALS_CMD_ID_ATTESTATIONRESPONSE,
                CLUSTER_OPERATIONAL_CREDENTIALS_CMD_ID_CERTIFICATECHAINRESPONSE,
                CLUSTER_OPERATIONAL_CREDENTIALS_CMD_ID_CSRRESPONSE,
                CLUSTER_OPERATIONAL_CREDENTIALS_CMD_ID_NOCRESPONSE,
            ],
        )?;


        self.set_attribute_u8(
            0,
            CLUSTER_ID_NETWORK_COMMISSIONING,
            CLUSTER_NETWORK_COMMISSIONING_ATTR_ID_MAXNETWORKS,
            1,
        );
        self.set_empty_array(
            0,
            CLUSTER_ID_NETWORK_COMMISSIONING,
            CLUSTER_NETWORK_COMMISSIONING_ATTR_ID_NETWORKS,
        );
        self.set_attribute_bool(
            0,
            CLUSTER_ID_NETWORK_COMMISSIONING,
            CLUSTER_NETWORK_COMMISSIONING_ATTR_ID_INTERFACEENABLED,
            true,
        );
        self.set_attribute_u8(
            0,
            CLUSTER_ID_NETWORK_COMMISSIONING,
            CLUSTER_NETWORK_COMMISSIONING_ATTR_ID_CONNECTMAXTIMESECONDS,
            120,
        );
        self.set_attribute_u8(
            0,
            CLUSTER_ID_NETWORK_COMMISSIONING,
            CLUSTER_NETWORK_COMMISSIONING_ATTR_ID_LASTNETWORKINGSTATUS,
            0,
        );
        self.set_attribute_u16(
            0,
            CLUSTER_ID_NETWORK_COMMISSIONING,
            CLUSTER_NETWORK_COMMISSIONING_ATTR_ID_SUPPORTEDTHREADFEATURES,
            0,
        );

        self.set_cluster_globals(
            0,
            CLUSTER_ID_NETWORK_COMMISSIONING,
            1,
            0x04, // FeatureMap = Ethernet
            &[
                CLUSTER_NETWORK_COMMISSIONING_ATTR_ID_MAXNETWORKS,
                CLUSTER_NETWORK_COMMISSIONING_ATTR_ID_NETWORKS,
                CLUSTER_NETWORK_COMMISSIONING_ATTR_ID_CONNECTMAXTIMESECONDS,
                CLUSTER_NETWORK_COMMISSIONING_ATTR_ID_INTERFACEENABLED,
                CLUSTER_NETWORK_COMMISSIONING_ATTR_ID_LASTNETWORKINGSTATUS,
                CLUSTER_NETWORK_COMMISSIONING_ATTR_ID_SUPPORTEDTHREADFEATURES,
            ],
            &[],
            &[],
        )?;

        self.set_empty_array(
            0,
            CLUSTER_ID_ACCESS_CONTROL,
            CLUSTER_ACCESS_CONTROL_ATTR_ID_ACL,
        );
        self.set_attribute_u16(
            0,
            CLUSTER_ID_ACCESS_CONTROL,
            CLUSTER_ACCESS_CONTROL_ATTR_ID_SUBJECTSPERACCESSCONTROLENTRY,
            4,
        );
        self.set_attribute_u16(
            0,
            CLUSTER_ID_ACCESS_CONTROL,
            CLUSTER_ACCESS_CONTROL_ATTR_ID_TARGETSPERACCESSCONTROLENTRY,
            3,
        );
        self.set_attribute_u16(
            0,
            CLUSTER_ID_ACCESS_CONTROL,
            CLUSTER_ACCESS_CONTROL_ATTR_ID_ACCESSCONTROLENTRIESPERFABRIC,
            4,
        );

        self.set_cluster_globals(
            0,
            CLUSTER_ID_ACCESS_CONTROL,
            2,
            0,
            &[
                CLUSTER_ACCESS_CONTROL_ATTR_ID_ACL,
                CLUSTER_ACCESS_CONTROL_ATTR_ID_SUBJECTSPERACCESSCONTROLENTRY,
                CLUSTER_ACCESS_CONTROL_ATTR_ID_TARGETSPERACCESSCONTROLENTRY,
                CLUSTER_ACCESS_CONTROL_ATTR_ID_ACCESSCONTROLENTRIESPERFABRIC,
            ],
            &[],
            &[],
        )?;

        self.set_attribute_u8(
            0,
            CLUSTER_ID_ADMINISTRATOR_COMMISSIONING,
            CLUSTER_ADMINISTRATOR_COMMISSIONING_ATTR_ID_WINDOWSTATUS,
            0, // WindowNotOpen
        );
        self.set_attribute_u8(
            0,
            CLUSTER_ID_ADMINISTRATOR_COMMISSIONING,
            CLUSTER_ADMINISTRATOR_COMMISSIONING_ATTR_ID_ADMINFABRICINDEX,
            0,
        );
        self.set_attribute_u16(
            0,
            CLUSTER_ID_ADMINISTRATOR_COMMISSIONING,
            CLUSTER_ADMINISTRATOR_COMMISSIONING_ATTR_ID_ADMINVENDORID,
            0,
        );

        self.set_cluster_globals(
            0,
            CLUSTER_ID_ADMINISTRATOR_COMMISSIONING,
            1,
            0,
            &[
                CLUSTER_ADMINISTRATOR_COMMISSIONING_ATTR_ID_WINDOWSTATUS,
                CLUSTER_ADMINISTRATOR_COMMISSIONING_ATTR_ID_ADMINFABRICINDEX,
                CLUSTER_ADMINISTRATOR_COMMISSIONING_ATTR_ID_ADMINVENDORID,
            ],
            &[
                CLUSTER_ADMINISTRATOR_COMMISSIONING_CMD_ID_OPENCOMMISSIONINGWINDOW,
                CLUSTER_ADMINISTRATOR_COMMISSIONING_CMD_ID_OPENBASICCOMMISSIONINGWINDOW,
                CLUSTER_ADMINISTRATOR_COMMISSIONING_CMD_ID_REVOKECOMMISSIONING,
            ],
            &[],
        )?;

        // WiFi Network Diagnostics cluster (0x60), attr 1 (kept for compat)
        self.set_attribute_u8(0, 0x60, 1, 3u8);

        Ok(())
    }

    pub fn set_empty_array(&mut self, endpoint: u16, cluster: u32, attribute: u32) {
        let mut buf = tlv::TlvBuffer::new();
        let _ = buf.write_array(2);
        let _ = buf.write_struct_end();
        self.set_attribute_raw(endpoint, cluster, attribute, &buf.data);
    }

    pub fn set_cluster_globals(
        &mut self,
        endpoint: u16,
        cluster: u32,
        revision: u16,
        feature_map: u32,
        attribute_ids: &[u32],
        accepted_cmds: &[u32],
        generated_cmds: &[u32],
    ) -> Result<()> {
        self.set_attribute_u16(endpoint, cluster, ATTR_CLUSTER_REVISION, revision);
        self.set_attribute_u32(endpoint, cluster, ATTR_FEATURE_MAP, feature_map);

        let mut buf = tlv::TlvBuffer::new();
        buf.write_array(2)?;
        for &id in attribute_ids {
            buf.write_uint32_notag(id)?;
        }
        buf.write_uint32_notag(ATTR_ATTRIBUTE_LIST)?;
        buf.write_uint32_notag(ATTR_FEATURE_MAP)?;
        buf.write_uint32_notag(ATTR_CLUSTER_REVISION)?;
        buf.write_uint32_notag(ATTR_EVENT_LIST)?;
        buf.write_uint32_notag(ATTR_ACCEPTED_CMD_LIST)?;
        buf.write_uint32_notag(ATTR_GENERATED_CMD_LIST)?;
        buf.write_struct_end()?;
        self.set_attribute_raw(endpoint, cluster, ATTR_ATTRIBUTE_LIST, &buf.data);

        self.set_empty_array(endpoint, cluster, ATTR_EVENT_LIST);

        let mut buf = tlv::TlvBuffer::new();
        buf.write_array(2)?;
        for &cmd in accepted_cmds {
            buf.write_uint32_notag(cmd)?;
        }
        buf.write_struct_end()?;
        self.set_attribute_raw(endpoint, cluster, ATTR_ACCEPTED_CMD_LIST, &buf.data);

        let mut buf = tlv::TlvBuffer::new();
        buf.write_array(2)?;
        for &cmd in generated_cmds {
            buf.write_uint32_notag(cmd)?;
        }
        buf.write_struct_end()?;
        self.set_attribute_raw(endpoint, cluster, ATTR_GENERATED_CMD_LIST, &buf.data);

        Ok(())
    }

    pub fn set_attribute_bool(&mut self, endpoint: u16, cluster: u32, attribute: u32, value: bool) {
        let mut buf = tlv::TlvBuffer::new();
        let _ = buf.write_bool(2, value);
        self.attributes
            .insert((endpoint, cluster, attribute), buf.data);
        self.dirty_attributes.insert((endpoint, cluster, attribute));
    }

    pub fn set_attribute_u8(&mut self, endpoint: u16, cluster: u32, attribute: u32, value: u8) {
        let mut buf = tlv::TlvBuffer::new();
        let _ = buf.write_uint8(2, value);
        self.attributes
            .insert((endpoint, cluster, attribute), buf.data);
        self.dirty_attributes.insert((endpoint, cluster, attribute));
    }

    pub fn set_attribute_u16(&mut self, endpoint: u16, cluster: u32, attribute: u32, value: u16) {
        let mut buf = tlv::TlvBuffer::new();
        let _ = buf.write_uint16(2, value);
        self.attributes
            .insert((endpoint, cluster, attribute), buf.data);
        self.dirty_attributes.insert((endpoint, cluster, attribute));
    }

    pub fn set_attribute_u32(&mut self, endpoint: u16, cluster: u32, attribute: u32, value: u32) {
        let mut buf = tlv::TlvBuffer::new();
        let _ = buf.write_uint32(2, value);
        self.attributes
            .insert((endpoint, cluster, attribute), buf.data);
        self.dirty_attributes.insert((endpoint, cluster, attribute));
    }

    pub fn set_attribute_u64(&mut self, endpoint: u16, cluster: u32, attribute: u32, value: u64) {
        let mut buf = tlv::TlvBuffer::new();
        let _ = buf.write_uint64(2, value);
        self.attributes
            .insert((endpoint, cluster, attribute), buf.data);
        self.dirty_attributes.insert((endpoint, cluster, attribute));
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
        self.dirty_attributes.insert((endpoint, cluster, attribute));
    }

    pub fn set_attribute_raw(&mut self, endpoint: u16, cluster: u32, attribute: u32, value: &[u8]) {
        self.attributes
            .insert((endpoint, cluster, attribute), value.to_vec());
        self.dirty_attributes.insert((endpoint, cluster, attribute));
    }
}


use std::collections::{HashMap, HashSet};

pub fn attr_set_bool(
    attributes: &mut HashMap<(u16, u32, u32), Vec<u8>>,
    dirty: &mut HashSet<(u16, u32, u32)>,
    ep: u16,
    cluster: u32,
    attr: u32,
    value: bool,
) {
    let mut buf = tlv::TlvBuffer::new();
    let _ = buf.write_bool(2, value);
    attributes.insert((ep, cluster, attr), buf.data);
    dirty.insert((ep, cluster, attr));
}

pub fn attr_get_bool(
    attributes: &HashMap<(u16, u32, u32), Vec<u8>>,
    ep: u16,
    cluster: u32,
    attr: u32,
) -> Option<bool> {
    attributes
        .get(&(ep, cluster, attr))
        .and_then(|v| tlv::decode_tlv(v).ok())
        .map(|item| bool::from(item.value))
}
