use anyhow::Result;
use matc::device::{Device, DeviceConfig};

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
    let config = DeviceConfig {
        pin: 123456,
        discriminator: 3840,
        listen_address: "0.0.0.0:5540".to_string(),
        vendor_id: 1049,
        product_id: 8005,
        dac_cert_path: "device-cert/dac-cert.pem".to_string(),
        pai_cert_path: "device-cert/pai-cert.pem".to_string(),
        dac_key_path: "device-cert/dac-key.pem".to_string(),
        hostname: "111111111111.local".to_string(),
    };
    println!("Device listening on {}", config.listen_address);
    println!(
        "manual paring code: {}",
        matc::onboarding::encode_manual_pairing_code(&matc::onboarding::OnboardingInfo {
            discriminator: config.discriminator,
            passcode: config.pin,
        })
    );
    println!("PIN: {}", config.pin);
    let mut device = Device::new(config, mdns.clone()).await?;

    device.run().await
}
