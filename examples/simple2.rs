/// this example assumes that certificates are present in pem directory and device is commissioned
/// these steps are done in simple.rs example
use std::sync::Arc;

use anyhow::Result;
use matc::{
    certmanager,
    clusters::codec::{level_control, on_off},
    controller, transport,
};

#[tokio::main]
async fn main() -> Result<()> {
    let fabric_id = 1000;
    let controller_id = 100;
    let device_id = 300;

    let cm: Arc<dyn certmanager::CertManager> = certmanager::FileCertManager::load("./pem")?;
    let transport = transport::Transport::new("0.0.0.0:5555").await?;
    let controller = controller::Controller::new(&cm, &transport, fabric_id)?;
    let connection = transport.create_connection("192.168.5.70:5540").await;

    let connection = controller
        .auth_sigma(&connection, device_id, controller_id)
        .await?;

    // send ON command to device
    on_off::on(&connection, 1).await?;

    // read ON/OFF state
    assert!(on_off::read_on_off(&connection, 1).await?);

    // send OFF command to device
    on_off::off(&connection, 1).await?;

    // read ON/OFF state
    assert!(!on_off::read_on_off(&connection, 1).await?);

    // send ON command to device
    on_off::on(&connection, 1).await?;

    // send MoveToLevel command
    level_control::move_to_level(&connection, 1, 50, Some(1000), 0, 0).await?;

    // read level
    let level = level_control::read_current_level(&connection, 1).await?;
    println!("{:?}", level);

    Ok(())
}
