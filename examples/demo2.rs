use std::sync::Arc;

use matc::{certmanager, controller, transport};


fn main() {
    let fabric_id = 0x110;
    let local_address = "0.0.0.0:5555";
    let device_address = "192.168.5.70:5540";
    let pin = 123456;
    let device_id = 600;
    let controller_id = 100;

    let cm: Arc<dyn certmanager::CertManager> = Arc::new(certmanager::FileCertManager::new(fabric_id, "./pem2"));
    let transport = transport::Transport::new(local_address).unwrap();
    let controller = controller::Controller::new(&cm, &transport, fabric_id);
    let connection = transport.create_connection(device_address);
    controller.commission(&connection, pin, device_id, controller_id).unwrap();

    let mut connection = controller.auth_sigma(&connection, device_id, controller_id).unwrap();
    connection.read_request(0, 0x1d, 0).unwrap();
}