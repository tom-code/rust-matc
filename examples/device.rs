use anyhow::Result;
use matc::clusters::defs::*;
use matc::device::{AppHandler, AttrContext, CommandResult, Device, DeviceConfig};
use matc::tlv;


struct OnOffHandler;

impl AppHandler for OnOffHandler {
    fn handle_command(
        &mut self,
        endpoint: u16,
        cluster: u32,
        command: u32,
        _payload: &tlv::TlvItem,
        attrs: &mut AttrContext,
    ) -> CommandResult {
        match (cluster, command) {
            (
                CLUSTER_ID_ON_OFF,
                CLUSTER_ON_OFF_CMD_ID_OFF | CLUSTER_ON_OFF_CMD_ID_ON | CLUSTER_ON_OFF_CMD_ID_TOGGLE,
            ) => {
                let new_val = match command {
                    CLUSTER_ON_OFF_CMD_ID_OFF => false,
                    CLUSTER_ON_OFF_CMD_ID_ON => true,
                    _ => !attrs.get_bool(endpoint, CLUSTER_ID_ON_OFF, CLUSTER_ON_OFF_ATTR_ID_ONOFF).unwrap_or(false),
                };
                attrs.set_bool(endpoint, CLUSTER_ID_ON_OFF, CLUSTER_ON_OFF_ATTR_ID_ONOFF, new_val);
                log::info!("OnOff: endpoint={} state={}", endpoint, new_val);
                CommandResult::Success
            }
            _ => CommandResult::Unhandled,
        }
    }
}


fn setup_app_endpoints(device: &mut Device) -> Result<()> {
    // EP1: On/Off Light (device type 0x0100)
    device.add_endpoint(1, 0x0100, 2)?;

    // OnOff cluster on EP1
    device.set_attribute_bool(1, CLUSTER_ID_ON_OFF, CLUSTER_ON_OFF_ATTR_ID_ONOFF, false);
    device.set_attribute_bool(1, CLUSTER_ID_ON_OFF, CLUSTER_ON_OFF_ATTR_ID_GLOBALSCENECONTROL, true);
    device.set_attribute_u16(1, CLUSTER_ID_ON_OFF, CLUSTER_ON_OFF_ATTR_ID_ONTIME, 0);
    device.set_attribute_u16(1, CLUSTER_ID_ON_OFF, CLUSTER_ON_OFF_ATTR_ID_OFFWAITTIME, 0);
    device.set_attribute_u8(1, CLUSTER_ID_ON_OFF, CLUSTER_ON_OFF_ATTR_ID_STARTUPONOFF, 0);
    device.add_cluster(
        1, CLUSTER_ID_ON_OFF, 6, 0,
        &[
            CLUSTER_ON_OFF_ATTR_ID_ONOFF,
            CLUSTER_ON_OFF_ATTR_ID_GLOBALSCENECONTROL,
            CLUSTER_ON_OFF_ATTR_ID_ONTIME,
            CLUSTER_ON_OFF_ATTR_ID_OFFWAITTIME,
            CLUSTER_ON_OFF_ATTR_ID_STARTUPONOFF,
        ],
        &[CLUSTER_ON_OFF_CMD_ID_OFF, CLUSTER_ON_OFF_CMD_ID_ON, CLUSTER_ON_OFF_CMD_ID_TOGGLE],
        &[],
    )?;

    // Identify cluster on EP1
    device.set_attribute_u16(1, CLUSTER_ID_IDENTIFY, CLUSTER_IDENTIFY_ATTR_ID_IDENTIFYTIME, 0);
    device.set_attribute_u8(1, CLUSTER_ID_IDENTIFY, CLUSTER_IDENTIFY_ATTR_ID_IDENTIFYTYPE, 0);
    device.add_cluster(
        1, CLUSTER_ID_IDENTIFY, 4, 0,
        &[CLUSTER_IDENTIFY_ATTR_ID_IDENTIFYTIME, CLUSTER_IDENTIFY_ATTR_ID_IDENTIFYTYPE],
        &[CLUSTER_IDENTIFY_CMD_ID_IDENTIFY],
        &[],
    )?;

    // Groups cluster on EP1
    device.set_attribute_u8(1, CLUSTER_ID_GROUPS, CLUSTER_GROUPS_ATTR_ID_NAMESUPPORT, 0);
    device.add_cluster(
        1, CLUSTER_ID_GROUPS, 4, 0,
        &[CLUSTER_GROUPS_ATTR_ID_NAMESUPPORT],
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
        advertise_addresses: Some(["192.168.1.23".parse().unwrap()].to_vec()),
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
                    is_short_discriminator: false,
                    vendor_id: None,
                    product_id: None,
                    discovery_capabilities: None,
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
