use matc::{clusters, devman::{DeviceManager, ManagerConfig}};
use anyhow::Result;



#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::new()
        .parse_default_env()
        .target(env_logger::Target::Stdout)
        .filter_level(log::LevelFilter::Trace)
        .format_timestamp(Some(env_logger::TimestampPrecision::Millis))
        .init();

    const FABRIC_ID: u64 = 100;
    const CONTROLLER_ID: u64 = 200;
    const NODE_ID: u64 = 300;
    const NAME: &str = "My Device";
    const LOCAL_ADDRESS: &str = "0.0.0.0:5555";
    const DATA_DIR: &str = "./matter-data";

    let devman = {
        let devman = DeviceManager::load(DATA_DIR).await;
        if devman.is_ok() {
            devman
        } else {
            println!("No existing config found, performing first-time setup...");
            let config = ManagerConfig {
                fabric_id: FABRIC_ID,
                controller_id: CONTROLLER_ID,
                local_address: LOCAL_ADDRESS.to_string(),
            };
            DeviceManager::create(DATA_DIR, config).await
        }
    }?;

    let conn = devman.commission("192.168.1.21:5540", 123456, NODE_ID, NAME).await?;
    let res = conn.read_request2(0, clusters::defs::CLUSTER_ID_DESCRIPTOR,
                                    clusters::defs::CLUSTER_DESCRIPTOR_ATTR_ID_SERVERLIST).await?;
    let endpoints = matc::clusters::codec::descriptor_cluster::decode_parts_list(&res).unwrap();
    println!("Endpoints: {:?}", endpoints);

    // drop connection - just to demonstrate how we can connect to the same device after it is commissioned
    drop(conn);
    tokio::time::sleep(std::time::Duration::from_secs(1)).await; // wait for the connection to be fully cleaned up

    println!("Reconnecting to device by name...");   
    let conn = devman.connect_by_name(NAME).await?;
    let res = conn.read_request2(0, clusters::defs::CLUSTER_ID_DESCRIPTOR,
                                    clusters::defs::CLUSTER_DESCRIPTOR_ATTR_ID_SERVERLIST).await?;
    let endpoints = matc::clusters::codec::descriptor_cluster::decode_parts_list(&res).unwrap();
    println!("Endpoints : {:?}", endpoints);

    Ok(())
}
