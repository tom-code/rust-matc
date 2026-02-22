/// Demo application for DeviceManager - simplified Matter device interaction.
///
/// Usage:
///   # First-time setup (creates CA, controller certs, config):
///   cargo run --example devman_demo -- init ./matter-data --fabric-id 1000 --controller-id 100
///
///   # Commission a device:
///   cargo run --example devman_demo -- -d ./matter-data commission 192.168.1.100:5540 300 123456 "kitchen light"
/// 
///   # Commission a device using manual pairing code and discovery:
///   cargo run --example devman_demo -- -d ./matter-data commission-with-discovery "0251-520-0076" 300 "kitchen light"
///
///   # List registered devices:
///   cargo run --example devman_demo -- -d ./matter-data list
///
///   # Send ON/OFF commands:
///   cargo run --example devman_demo -- -d ./matter-data on "kitchen light"
///   cargo run --example devman_demo -- -d ./matter-data off "kitchen light"
use anyhow::Result;
use clap::{Parser, Subcommand};
use matc::{clusters, devman::{DeviceManager, ManagerConfig}};
use std::time::Duration;

const DEFAULT_DATA_DIR: &str = "./matter-data";
const DEFAULT_LOCAL_ADDRESS: &str = "0.0.0.0:5555";

#[derive(Parser, Debug)]
#[command(name = "devman_demo", about = "Matter device manager demo")]
struct Cli {
    #[clap(long)]
    #[arg(global = true, default_value_t = false)]
    verbose: bool,

    /// Data directory (config, certs, device registry)
    #[clap(short, long)]
    #[arg(global = true, default_value_t = DEFAULT_DATA_DIR.to_string())]
    data_dir: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Initialize device manager (create CA, controller, config)
    Init {
        #[clap(long, default_value_t = 1000)]
        fabric_id: u64,

        #[clap(long, default_value_t = 100)]
        controller_id: u64,

        #[clap(long, default_value_t = DEFAULT_LOCAL_ADDRESS.to_string())]
        local_address: String,
    },
    /// Commission a device
    Commission {
        /// Device address (ip:port)
        address: String,
        /// Node ID to assign
        node_id: u64,
        /// Commissioning PIN
        pin: u32,
        /// Friendly name
        name: String,
    },
    CommissionWithDiscovery {
        /// Manual pairing code
        pairing_code: String,
        /// Node ID to assign
        node_id: u64,
        /// Friendly name
        name: String,
    },
    /// List registered devices
    List,
    /// Send ON command
    On {
        /// Device name or node ID
        device: String,
    },
    /// Send OFF command
    Off {
        /// Device name or node ID
        device: String,
    },
    /// Send Toggle command
    Toggle {
        /// Device name or node ID
        device: String,
    },
    /// Remove device from registry
    Remove {
        /// Device name or node ID
        device: String,
    },
    /// Rename device
    Rename {
        /// Current device name or node ID
        device: String,
        /// New name
        new_name: String,
    },
}

async fn connect_by_name_or_id(dm: &DeviceManager, device: &str) -> Result<matc::controller::Connection> {
    // Try parsing as node_id first, fall back to name lookup
    if let Ok(node_id) = device.parse::<u64>() {
        if dm.get_device(node_id)?.is_some() {
            return dm.connect(node_id).await;
        }
    }
    dm.connect_by_name(device).await
}

fn resolve_node_id(dm: &DeviceManager, device: &str) -> Result<u64> {
    if let Ok(node_id) = device.parse::<u64>() {
        if dm.get_device(node_id)?.is_some() {
            return Ok(node_id);
        }
    }
    let dev = dm.get_device_by_name(device)?
        .ok_or_else(|| anyhow::anyhow!("device '{}' not found", device))?;
    Ok(dev.node_id)
}

async fn discover(discriminator: u16) -> Result<(Vec<std::net::IpAddr>, u16)> {
    let (mdns, mut receiver) = matc::mdns2::MdnsService::new().await?;
    mdns.add_query("_matterc._udp.local", 0xff, Duration::from_secs(3)).await;
    while let Some(dns) = receiver.recv().await {
        if let matc::mdns2::MdnsEvent::ServiceDiscovered {name, records: _, target } = dns {
            if name != "_matterc._udp.local." {
                continue;
            }
            let info = matc::discover::extract_matter_info(&target, &mdns).await;
            let info = match info {
                Ok(info) => info,
                Err(e) => {
                    log::debug!("Failed to extract Matter info from {}: {}", target, e);
                    continue;
                }
            };
            if let Some(ref d) = info.discriminator {
                if *d == discriminator.to_string() {
                    println!("Found device: {:?}", info);
                    mdns.shutdown();
                    return Ok((info.ips, info.port.unwrap_or(5540)));
                }
            }
        }
    }
    anyhow::bail!("No device found with discriminator {}", discriminator)
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let log_level = if cli.verbose {
        log::LevelFilter::Trace
    } else {
        log::LevelFilter::Error
    };
    env_logger::Builder::new()
        .parse_default_env()
        .target(env_logger::Target::Stdout)
        .filter_level(log_level)
        .format_timestamp(Some(env_logger::TimestampPrecision::Millis))
        .init();

    let data_dir = &cli.data_dir;

    match cli.command {
        Commands::Init { fabric_id, controller_id, local_address } => {
            let config = ManagerConfig {
                fabric_id,
                controller_id,
                local_address,
            };
            DeviceManager::create(data_dir, config).await?;
            println!("Device manager initialized in {}", data_dir);
        }
        Commands::Commission { address, node_id, pin, name } => {
            let dm = DeviceManager::load(data_dir).await?;
            let conn = dm.commission(&address, pin, node_id, &name).await?;
            println!("Commissioned '{}' (node {}) at {}", name, node_id, address);

            // List endpoints
            let res = conn.read_request2(0, clusters::defs::CLUSTER_ID_DESCRIPTOR,
                                         clusters::defs::CLUSTER_DESCRIPTOR_ATTR_ID_SERVERLIST).await;
            if let Ok(matc::tlv::TlvItemValue::List(l)) = res {
                println!("Supported clusters:");
                for c in l {
                    if let matc::tlv::TlvItemValue::Int(v) = c.value {
                        match clusters::names::get_cluster_name(v as u32) {
                            Some(name) => println!("  {}", name),
                            None => println!("  unknown (0x{:x})", v),
                        }
                    }
                }
            }
        }
        Commands::CommissionWithDiscovery { pairing_code, node_id, name } => {
            let dm = DeviceManager::load(data_dir).await?;
            let onboarding_info = matc::onboarding::decode_manual_pairing_code(&pairing_code).unwrap();
            println!("Discovering device with discriminator {}...", onboarding_info.discriminator);
            let (ips, port) = discover(onboarding_info.discriminator).await?;
            if ips.is_empty() {
                println!("No device found with discriminator {}", onboarding_info.discriminator);
                return Ok(());
            }
            println!("Found device at IPs: {:?}", ips);
            for ip in &ips {
                println!("Attempting to commission at {}:{}...", ip, port);
                let address = if ip.is_ipv6() {
                    format!("[{}]:{}", ip, port)
                } else {
                    format!("{}:{}", ip, port)
                };

                let pin = onboarding_info.passcode;
                match dm.commission(&address, pin, node_id, &name).await {
                    Ok(connection) => {
                        println!("Commissioned '{}' (node {}) at {}", name, node_id, address);
                        let resptlv = connection
                            .read_request2(
                                0,
                                clusters::defs::CLUSTER_ID_DESCRIPTOR,
                                clusters::defs::CLUSTER_DESCRIPTOR_ATTR_ID_PARTSLIST,
                            )
                            .await
                            .unwrap();
                        let mut endpoints = matc::clusters::codec::descriptor_cluster::decode_parts_list(&resptlv).unwrap();
                        println!("Endpoints: {:?}", endpoints);
                        endpoints.push(0);
                        for ep in endpoints {
                            let resptlv = connection
                                .read_request2(
                                    ep,
                                    clusters::defs::CLUSTER_ID_DESCRIPTOR,
                                    clusters::defs::CLUSTER_DESCRIPTOR_ATTR_ID_SERVERLIST,
                                )
                                .await.unwrap();
                            let clusters = matc::clusters::codec::descriptor_cluster::decode_server_list(&resptlv).unwrap();
                            let names = clusters.iter().map(|c| {
                                match clusters::names::get_cluster_name(*c) {
                                    Some(name) => name.to_string(),
                                    None => format!("unknown (0x{:x})", c),
                                }
                            }).collect::<Vec<_>>();
                            println!("Supported clusters on endpoint {:?}: {:?}", ep, names);
                        }
                        return Ok(());
                    }
                    Err(e) => {
                        println!("Failed to commission at {}: {}. Trying next IP if available...", address, e);
                        tokio::time::sleep(Duration::from_secs(3)).await; // brief pause before next attempt
                    }
                }
            }
            println!("Failed to commission '{}' (node {}) at any discovered IPs", name, node_id);
        }
        Commands::List => {
            let dm = DeviceManager::load(data_dir).await?;
            let devices = dm.list_devices()?;
            if devices.is_empty() {
                println!("No devices registered.");
            } else {
                println!("{:<10} {:<25} Name", "Node ID", "Address");
                println!("{}", "-".repeat(60));
                for d in devices {
                    println!("{:<10} {:<25} {}", d.node_id, d.address, d.name);
                }
            }
        }
        Commands::On { device } => {
            let dm = DeviceManager::load(data_dir).await?;
            let conn = connect_by_name_or_id(&dm, &device).await?;
            conn.invoke_request(1, clusters::defs::CLUSTER_ID_ON_OFF,
                                clusters::defs::CLUSTER_ON_OFF_CMD_ID_ON, &[]).await?;
            println!("ON sent to '{}'", device);
        }
        Commands::Off { device } => {
            let dm = DeviceManager::load(data_dir).await?;
            let conn = connect_by_name_or_id(&dm, &device).await?;
            conn.invoke_request(1, clusters::defs::CLUSTER_ID_ON_OFF,
                                clusters::defs::CLUSTER_ON_OFF_CMD_ID_OFF, &[]).await?;
            println!("OFF sent to '{}'", device);
        }
        Commands::Toggle { device } => {
            let dm = DeviceManager::load(data_dir).await?;
            let conn = connect_by_name_or_id(&dm, &device).await?;
            conn.invoke_request(1, clusters::defs::CLUSTER_ID_ON_OFF,
                                clusters::defs::CLUSTER_ON_OFF_CMD_ID_TOGGLE, &[]).await?;
            println!("TOGGLE sent to '{}'", device);
        }
        Commands::Remove { device } => {
            let dm = DeviceManager::load(data_dir).await?;
            let node_id = resolve_node_id(&dm, &device)?;
            dm.remove_device(node_id)?;
            println!("Removed device (node {})", node_id);
        }
        Commands::Rename { device, new_name } => {
            let dm = DeviceManager::load(data_dir).await?;
            let node_id = resolve_node_id(&dm, &device)?;
            dm.rename_device(node_id, &new_name)?;
            println!("Renamed device (node {}) to '{}'", node_id, new_name);
        }
    }

    Ok(())
}
