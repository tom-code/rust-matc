
/// this example assumes that certificates are present in pem directory and device is commissioned
/// these steps are done in simple.rs example



use std::sync::Arc;

use matc::{certmanager, controller, tlv, transport};
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let fabric_id = 1000;
    let controller_id = 100;
    let device_id = 300;


    let cm: Arc<dyn certmanager::CertManager> = certmanager::FileCertManager::load("./pem")?;
    let transport = transport::Transport::new("0.0.0.0:5555").await?;
    let controller = controller::Controller::new(&cm, &transport, fabric_id)?;
    let connection = transport.create_connection("192.168.5.70:5540").await;

    let mut connection = controller.auth_sigma(&connection, device_id, controller_id).await?;

    // send ON command to device
    connection.invoke_request(1, 0x6, 1, &[]).await?;

    // read ON/OFF state
    let res = connection.read_request2(1, 6, 0).await?;
    assert!(res == tlv::TlvItemValue::Bool(true));

    // send OFF command to device
    connection.invoke_request(1, 0x6, 0, &[]).await?;

    // read ON/OFF state
    let res = connection.read_request2(1, 6, 0).await?;
    assert!(res == tlv::TlvItemValue::Bool(false));

    // send ON command to device
    connection.invoke_request(1, 0x6, 0, &[]).await?;

    // send MoveToLevel command
    let tlv = tlv::TlvItemEnc {
        tag: 0,
        value: tlv::TlvItemValueEnc::StructInvisible(vec![
            tlv::TlvItemEnc { tag: 0, value: tlv::TlvItemValueEnc::UInt8(50)   }, // level
            tlv::TlvItemEnc { tag: 1, value: tlv::TlvItemValueEnc::UInt16(1000)}, // transition time
            tlv::TlvItemEnc { tag: 2, value: tlv::TlvItemValueEnc::UInt8(0)    }, // options mask
            tlv::TlvItemEnc { tag: 3, value: tlv::TlvItemValueEnc::UInt8(0)    }, // options override
            ])
    }.encode()?;
    connection.invoke_request(1, 0x8, 0, &tlv).await?;

    // read level
    let res = connection.read_request2(1, 8, 0).await?;
    println!("{:?}", res);


    Ok(())
}