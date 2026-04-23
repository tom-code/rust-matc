//! BLE commissioning example.
//!
//! Commissions a Wi-Fi Matter device that is advertising over BLE, provisions
//! Wi-Fi credentials, and then toggles the On/Off cluster to verify the connection.
//!
//! # Prerequisites
//! * Run `cargo run --example demo -- ca-bootstrap` and `ca-create-controller 100` first.
//! * The device must be in BLE commissioning mode (factory-fresh or reset).
//!
//! # Usage
//! ```text
//! cargo run --features ble --example simple-ble -- \
//!     --pairing-code "0251-520-0076" \
//!     --ssid "MyWifi" \
//!     --password "secret" \
//!     --node-id 400 \
//!     --name "ble-light"
//! ```

#[cfg(not(feature = "ble"))]
fn main() {
    eprintln!("This example requires the 'ble' feature: cargo run --features ble --example simple-ble");
    std::process::exit(1);
}

#[cfg(feature = "ble")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    //env_logger::init();
    env_logger::Builder::new()
        .parse_default_env()
        .target(env_logger::Target::Stdout)
        .filter_level(log::LevelFilter::Trace)
        .format_timestamp(Some(env_logger::TimestampPrecision::Millis))
        .init();

    let args: Vec<String> = std::env::args().collect();
    let pairing_code = flag_value(&args, "--pairing-code").unwrap_or("0251-520-0076");
    let ssid         = flag_value(&args, "--ssid").unwrap_or("MyWifi");
    let password     = flag_value(&args, "--password").unwrap_or("password");
    let node_id: u64 = flag_value(&args, "--node-id").unwrap_or("400").parse().unwrap_or(400);
    let name         = flag_value(&args, "--name").unwrap_or("ble-device");
    let data_dir     = flag_value(&args, "--data-dir").unwrap_or("./matter-data");

    let dm = matc::devman::DeviceManager::load(data_dir).await?;

    println!("Scanning for BLE commissionable device (pairing code: {})…", pairing_code);
    let conn = dm
        .commission_ble_with_code(
            pairing_code,
            node_id,
            name,
            matc::NetworkCreds::WiFi {
                ssid: ssid.as_bytes().to_vec(),
                creds: password.as_bytes().to_vec(),
            },
        )
        .await?;

    println!("Commissioned! Sending ON command…");
    conn.invoke_request(
        1,
        matc::clusters::defs::CLUSTER_ID_ON_OFF,
        matc::clusters::defs::CLUSTER_ON_OFF_CMD_ID_ON,
        &[],
    )
    .await?;

    println!("Done.");
    Ok(())
}

#[cfg(feature = "ble")]
fn flag_value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.windows(2)
        .find(|w| w[0] == flag)
        .map(|w| w[1].as_str())
}
