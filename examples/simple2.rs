/// this example assumes that certificates are present in pem directory and device is commissioned
/// these steps are done in simple.rs example
use std::sync::Arc;

use anyhow::Result;
use matc::{certmanager, clusters, controller, tlv, transport};

#[tokio::main]
async fn main() -> Result<()> {
    let fabric_id = 1000;
    let controller_id = 100;
    let device_id = 300;

    let cm: Arc<dyn certmanager::CertManager> = certmanager::FileCertManager::load("./pem")?;
    let transport = transport::Transport::new("0.0.0.0:5555").await?;
    let controller = controller::Controller::new(&cm, &transport, fabric_id)?;
    let connection = transport.create_connection("192.168.5.70:5540").await;

    let mut connection = controller
        .auth_sigma(&connection, device_id, controller_id)
        .await?;

    // send ON command to device
    connection
        .invoke_request(1, 0x6, clusters::defs::CLUSTER_ON_OFF_CMD_ID_ON, &[])
        .await?;

    // read ON/OFF state
    let res = connection
        .read_request2(
            1,
            clusters::defs::CLUSTER_ID_ON_OFF,
            clusters::defs::CLUSTER_ON_OFF_ATTR_ID_ONOFF,
        )
        .await?;
    assert!(res == tlv::TlvItemValue::Bool(true));

    // send OFF command to device
    connection
        .invoke_request(
            1,
            clusters::defs::CLUSTER_ID_ON_OFF,
            clusters::defs::CLUSTER_ON_OFF_CMD_ID_OFF,
            &[],
        )
        .await?;

    // read ON/OFF state
    let res = connection
        .read_request2(
            1,
            clusters::defs::CLUSTER_ID_ON_OFF,
            clusters::defs::CLUSTER_ON_OFF_ATTR_ID_ONOFF,
        )
        .await?;
    assert!(res == tlv::TlvItemValue::Bool(false));

    // send ON command to device
    connection
        .invoke_request(
            1,
            clusters::defs::CLUSTER_ID_ON_OFF,
            clusters::defs::CLUSTER_ON_OFF_CMD_ID_ON,
            &[],
        )
        .await?;

    // send MoveToLevel command
    let tlv = std::convert::Into::<tlv::TlvItemEnc>::into((
        0,
        tlv::TlvItemValueEnc::StructInvisible(vec![
            (0, tlv::TlvItemValueEnc::UInt8(50)).into(), // level
            (1, tlv::TlvItemValueEnc::UInt16(1000)).into(), // transition time
            (2, tlv::TlvItemValueEnc::UInt8(0)).into(), // options mask
            (3, tlv::TlvItemValueEnc::UInt8(0)).into(), // options override
        ]))).encode()?;

    connection
        .invoke_request(
            1,
            clusters::defs::CLUSTER_ID_LEVEL_CONTROL,
            clusters::defs::CLUSTER_LEVEL_CONTROL_CMD_ID_MOVETOLEVEL,
            &tlv,
        )
        .await?;

    // read level
    let res = connection
        .read_request2(
            1,
            clusters::defs::CLUSTER_ID_LEVEL_CONTROL,
            clusters::defs::CLUSTER_LEVEL_CONTROL_ATTR_ID_CURRENTLEVEL,
        )
        .await?;
    println!("{:?}", res);

    Ok(())
}
