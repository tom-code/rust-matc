use std::collections::{HashMap, HashSet};

use anyhow::Result;
use matc::clusters::defs::*;
use matc::device::{AppHandler, CommandResult, Device, DeviceConfig, attr_get_bool, attr_set_bool};
use matc::tlv;


struct OnOffHandler;

impl AppHandler for OnOffHandler {
    fn handle_command(
        &mut self,
        endpoint: u16,
        cluster: u32,
        command: u32,
        _payload: &tlv::TlvItem,
        attributes: &mut HashMap<(u16, u32, u32), Vec<u8>>,
        dirty: &mut HashSet<(u16, u32, u32)>,
    ) -> CommandResult {
        match (cluster, command) {
            (
                CLUSTER_ID_ON_OFF,
                CLUSTER_ON_OFF_CMD_ID_OFF | CLUSTER_ON_OFF_CMD_ID_ON | CLUSTER_ON_OFF_CMD_ID_TOGGLE,
            ) => {
                let new_val = match command {
                    CLUSTER_ON_OFF_CMD_ID_OFF => false,
                    CLUSTER_ON_OFF_CMD_ID_ON => true,
                    _ => {
                        // Toggle: read current state
                        let current = attr_get_bool(
                            attributes,
                            endpoint,
                            CLUSTER_ID_ON_OFF,
                            CLUSTER_ON_OFF_ATTR_ID_ONOFF,
                        )
                        .unwrap_or(false);
                        !current
                    }
                };
                attr_set_bool(
                    attributes,
                    dirty,
                    endpoint,
                    CLUSTER_ID_ON_OFF,
                    CLUSTER_ON_OFF_ATTR_ID_ONOFF,
                    new_val,
                );
                log::info!("OnOff: endpoint={} state={}", endpoint, new_val);
                CommandResult::Success
            }
            _ => CommandResult::Unhandled,
        }
    }
}


fn setup_app_endpoints(device: &mut Device) -> Result<()> {
    // --- OnOff (0x06) on EP1 ---
    device.set_attribute_bool(1, CLUSTER_ID_ON_OFF, CLUSTER_ON_OFF_ATTR_ID_ONOFF, false);
    device.set_attribute_bool(1, CLUSTER_ID_ON_OFF, CLUSTER_ON_OFF_ATTR_ID_GLOBALSCENECONTROL, true);
    device.set_attribute_u16(1, CLUSTER_ID_ON_OFF, CLUSTER_ON_OFF_ATTR_ID_ONTIME, 0);
    device.set_attribute_u16(1, CLUSTER_ID_ON_OFF, CLUSTER_ON_OFF_ATTR_ID_OFFWAITTIME, 0);
    device.set_attribute_u8(1, CLUSTER_ID_ON_OFF, CLUSTER_ON_OFF_ATTR_ID_STARTUPONOFF, 0);
    device.set_cluster_globals(
        1,
        CLUSTER_ID_ON_OFF,
        6,
        0,
        &[
            CLUSTER_ON_OFF_ATTR_ID_ONOFF,
            CLUSTER_ON_OFF_ATTR_ID_GLOBALSCENECONTROL,
            CLUSTER_ON_OFF_ATTR_ID_ONTIME,
            CLUSTER_ON_OFF_ATTR_ID_OFFWAITTIME,
            CLUSTER_ON_OFF_ATTR_ID_STARTUPONOFF,
        ],
        &[
            CLUSTER_ON_OFF_CMD_ID_OFF,
            CLUSTER_ON_OFF_CMD_ID_ON,
            CLUSTER_ON_OFF_CMD_ID_TOGGLE,
        ],
        &[],
    )?;

    // --- Identify (0x03) on EP1 ---
    device.set_attribute_u16(1, CLUSTER_ID_IDENTIFY, CLUSTER_IDENTIFY_ATTR_ID_IDENTIFYTIME, 0);
    device.set_attribute_u8(1, CLUSTER_ID_IDENTIFY, CLUSTER_IDENTIFY_ATTR_ID_IDENTIFYTYPE, 0);
    device.set_cluster_globals(
        1,
        CLUSTER_ID_IDENTIFY,
        4,
        0,
        &[
            CLUSTER_IDENTIFY_ATTR_ID_IDENTIFYTIME,
            CLUSTER_IDENTIFY_ATTR_ID_IDENTIFYTYPE,
        ],
        &[CLUSTER_IDENTIFY_CMD_ID_IDENTIFY],
        &[],
    )?;

    // --- Groups (0x04) on EP1 ---
    device.set_attribute_u8(1, CLUSTER_ID_GROUPS, CLUSTER_GROUPS_ATTR_ID_NAMESUPPORT, 0);
    device.set_cluster_globals(
        1,
        CLUSTER_ID_GROUPS,
        4,
        0,
        &[
            CLUSTER_GROUPS_ATTR_ID_NAMESUPPORT,
        ],
        &[
            CLUSTER_GROUPS_CMD_ID_ADDGROUP,
            CLUSTER_GROUPS_CMD_ID_VIEWGROUP,
            CLUSTER_GROUPS_CMD_ID_GETGROUPMEMBERSHIP,
            CLUSTER_GROUPS_CMD_ID_REMOVEGROUP,
            CLUSTER_GROUPS_CMD_ID_REMOVEALLGROUPS,
            CLUSTER_GROUPS_CMD_ID_ADDGROUPIFIDENTIFYING,
        ],
        &[
            CLUSTER_GROUPS_CMD_ID_ADDGROUPRESPONSE,
            CLUSTER_GROUPS_CMD_ID_VIEWGROUPRESPONSE,
            CLUSTER_GROUPS_CMD_ID_GETGROUPMEMBERSHIPRESPONSE,
            CLUSTER_GROUPS_CMD_ID_REMOVEGROUPRESPONSE,
        ],
    )?;

    // --- Descriptor (0x1D) on EP1 ---
    let mut buf = matc::tlv::TlvBuffer::new();
    buf.write_array(2)?;
    buf.write_anon_struct()?;
    buf.write_uint32(0, 0x0100)?; // DeviceType = On/Off Light
    buf.write_uint16(1, 2)?;      // Revision = 2
    buf.write_struct_end()?;
    buf.write_struct_end()?;
    device.set_attribute_raw(1, CLUSTER_ID_DESCRIPTOR, CLUSTER_DESCRIPTOR_ATTR_ID_DEVICETYPELIST, &buf.data);

    let mut buf = matc::tlv::TlvBuffer::new();
    buf.write_array(2)?;
    buf.write_uint32_notag(CLUSTER_ID_IDENTIFY)?;
    buf.write_uint32_notag(CLUSTER_ID_GROUPS)?;
    buf.write_uint32_notag(CLUSTER_ID_ON_OFF)?;
    buf.write_uint32_notag(CLUSTER_ID_DESCRIPTOR)?;
    buf.write_struct_end()?;
    device.set_attribute_raw(1, CLUSTER_ID_DESCRIPTOR, CLUSTER_DESCRIPTOR_ATTR_ID_SERVERLIST, &buf.data);

    device.set_empty_array(1, CLUSTER_ID_DESCRIPTOR, CLUSTER_DESCRIPTOR_ATTR_ID_CLIENTLIST);
    device.set_empty_array(1, CLUSTER_ID_DESCRIPTOR, CLUSTER_DESCRIPTOR_ATTR_ID_PARTSLIST);
    device.set_cluster_globals(
        1,
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

    // Update EP0 Descriptor PartsList to include EP1
    let mut buf = matc::tlv::TlvBuffer::new();
    buf.write_array(2)?;
    buf.write_uint16_notag(1)?;
    buf.write_struct_end()?;
    device.set_attribute_raw(0, CLUSTER_ID_DESCRIPTOR, CLUSTER_DESCRIPTOR_ATTR_ID_PARTSLIST, &buf.data);

    // Register OnOff state for persistence across restarts
    device.add_persisted_attribute(1, CLUSTER_ID_ON_OFF, CLUSTER_ON_OFF_ATTR_ID_ONOFF);

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::new()
        .parse_default_env()
        .target(env_logger::Target::Stdout)
        .filter_level(log::LevelFilter::Trace)
        .format_timestamp(Some(env_logger::TimestampPrecision::Millis))
        .init();

    let (mdns, mut receiver) = matc::mdns2::MdnsService::new().await.unwrap();
    tokio::spawn(async move {
        while let Some(_event) = receiver.recv().await {
            //log::info!("mDNS event: {:?}", event);
        }
    });
    let state_dir = "device-state".to_string();
    let config = DeviceConfig {
        pin: 123456,
        discriminator: 3840,
        listen_address: "0.0.0.0:5540".to_string(),
        vendor_id: 0xFFF1,
        product_id: 0x8000,
        dac_cert_path: "device-cert/dac-cert.pem".to_string(),
        pai_cert_path: "device-cert/pai-cert.pem".to_string(),
        dac_key_path: "device-cert/dac-key.pem".to_string(),
        hostname: "111111111111.local".to_string(),
        state_dir: Some(state_dir.clone()),
        vendor_name: "YUTANI".to_string(),
        product_name: "ForeverLight".to_string(),
        hardware_version: 1,
        software_version: 3,
        serial_number: "YULISN00001".to_string(),
        unique_id: "YULIUID00001".to_string(),
    };
    println!("Device listening on {}", config.listen_address);

    let mut device = match Device::from_persisted_state(config.clone(), mdns.clone(), &state_dir).await {
        Ok(d) => {
            println!("Restored device from saved state in '{}'", state_dir);
            d
        }
        Err(_) => {
            println!("No saved state found — starting fresh");
            println!(
                "manual pairing code: {}",
                matc::onboarding::encode_manual_pairing_code(&matc::onboarding::OnboardingInfo {
                    discriminator: config.discriminator,
                    passcode: config.pin,
                })
            );
            println!("PIN: {}", config.pin);
            Device::new(config, mdns.clone()).await?
        }
    };

    setup_app_endpoints(&mut device)?;

    let mut handler = OnOffHandler;
    device.run(&mut handler).await
}
