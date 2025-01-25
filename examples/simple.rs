/// This example assumes that:
/// - certificates are not yet created (there is no pem directory)
/// - device is ready to be commissioned
/// - device implements ON/OFF cluster
use std::sync::Arc;

use anyhow::Result;
use matc::{certmanager, clusters, controller, tlv::TlvItemValue, transport};

#[tokio::main]
async fn main() -> Result<()> {
    let fabric_id = 1000;
    let controller_id = 100;
    let device_id = 300;
    let pin = 123456;

    // CA creation - shall be done only once
    // certificates are stored in pem directory and are reused to access commissioned devices
    // remove following three lines if basic certificates are already created
    let cm = certmanager::FileCertManager::new(fabric_id, "./pem");
    cm.bootstrap()?;
    cm.create_user(controller_id)?;

    let cm: Arc<dyn certmanager::CertManager> = certmanager::FileCertManager::load("./pem")?;
    let transport = transport::Transport::new("0.0.0.0:5555").await?;
    let controller = controller::Controller::new(&cm, &transport, fabric_id)?;
    let connection = transport.create_connection("192.168.5.70:5540").await;

    // commission device (push CA cert, sign its cert, set controller id)
    let mut connection = controller
        .commission(&connection, pin, device_id, controller_id)
        .await?;

    // send ON command to device
    connection
        .invoke_request(
            1,
            clusters::defs::CLUSTER_ID_ON_OFF,
            clusters::defs::CLUSTER_ON_OFF_CMD_ID_ON,
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
    assert!(res == TlvItemValue::Bool(true));

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
    assert!(res == TlvItemValue::Bool(false));

    Ok(())
}
