use std::{
    sync::Arc,
    time::{self, Duration},
};

use anyhow::Result;
use clap::{Parser, Subcommand};
use matc::{
    certmanager::{self, FileCertManager},
    clusters::{self, defs::{CLUSTER_DOOR_LOCK_CMD_ID_GETUSER, CLUSTER_ID_DOOR_LOCK}},
    controller, discover, messages, onboarding, tlv::{self, TlvItem}, transport,
};

const DEFAULT_FABRIC: u64 = 0x110;
const DEFAULT_LOCAL_ADDRESS: &str = "0.0.0.0:5555";
const DEFAULT_CERT_PATH: &str = "./pem";

const DEFAULT_DEVICE_ADDRESS: &str = "192.168.5.108:5540";
#[derive(Parser, Debug)]
#[command()]
struct Cli {
    #[clap(long)]
    #[arg(global = true, default_value_t = false)]
    verbose: bool,

    #[clap(long)]
    #[arg(global = true, default_value_t = DEFAULT_CERT_PATH.to_string())]
    cert_path: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Commission device
    Commission {
        #[clap(long)]
        #[arg(default_value_t=DEFAULT_LOCAL_ADDRESS.to_string())]
        local_address: String,

        device_address: String,
        controller_id: u64,
        device_id: u64,
        pin: u32,
    },
    ListSupportedClusters {
        #[clap(long)]
        #[arg(default_value_t=DEFAULT_LOCAL_ADDRESS.to_string())]
        local_address: String,

        device_address: String,
        controller_id: u64,
        device_id: u64,
        endpoint: u16,
    },
    Discover {
        #[clap(long)]
        #[arg(global = true, default_value_t = 5)]
        timeout: u64,

        #[command(subcommand)]
        discover: DiscoverCommand,
    },
    /*ListFabrics {
        #[clap(long)]
        #[arg(default_value_t = DEFAULT_FABRIC)]
        fabric_id: u64,

        #[clap(long)]
        #[arg(default_value_t=DEFAULT_LOCAL_ADDRESS.to_string())]
        local_address: String,

        device_address: String,
        controller_id: u64,
        device_id: u64,
    },*/
    /// Initialize CA - generate CA keys and certificate
    CaBootstrap {
        #[clap(long)]
        #[arg(default_value_t = DEFAULT_FABRIC)]
        fabric_id: u64,
    },
    DecodeManualPairingCode {
        code: String,
    },
    /// Create key and certificate for controller
    CaCreateController {
        controller_id: u64,
    },
    Command {
        #[clap(long)]
        #[arg(global = true, default_value_t = DEFAULT_LOCAL_ADDRESS.to_string())]
        local_address: String,

        #[clap(long)]
        #[arg(global = true, default_value_t = DEFAULT_DEVICE_ADDRESS.to_string())]
        device_address: String,

        #[clap(long)]
        #[arg(global = true, default_value_t = 100)]
        controller_id: u64,

        #[clap(long)]
        #[arg(global = true, default_value_t = 300)]
        device_id: u64,

        #[clap(long)]
        #[arg(global = true, default_value_t = 1)]
        endpoint: u16,

        #[command(subcommand)]
        command: CommandCommand,
    },
}

#[derive(Subcommand, Debug)]
enum CommandCommand {
    Read {
        endpoint: u16,
        cluster: u32,
        attr: u32,
    },
    InvokeCommandOn {},
    InvokeCommandOff {},
    InvokeCommandMoveToLevel {
        level: u8,
    },
    InvokeCommandMoveToHue {
        hue: u8,
    },
    InvokeCommandUpdateFabricLabel {
        label: String,
    },
    InvokeCommandRemoveFabric {
        index: u8,
    },
    ListSupportedClusters {
        endpoint: u16,
    },
    ListSupportedClusters2 {
        endpoint: u16,
    },
    ListParts {},
    ListBridgedDevices {},
    ListAttributes {},
    ListDevices {},
    StartCommissioning {
        pin: u32,

        #[arg(default_value_t = 1000)]
        iterations: u32,

        #[arg(default_value_t = 1000)]
        discriminator: u16,

        #[arg(default_value_t = 200)]
        timeout: u16,
    },
    MonitorDoorState{},
    Test2{},
}
#[derive(Subcommand, Debug)]
enum DiscoverCommand {
    Commissionable {},
    Commissioned {},
    Commissioned2 {
        #[arg(long)]
        device_id: Option<u64>,
    },
}

async fn create_connection(
    local_address: &str,
    device_address: &str,
    device_id: u64,
    controller_id: u64,
    cert_path: &str,
) -> Result<controller::Connection> {
    let cm: Arc<dyn certmanager::CertManager> = certmanager::FileCertManager::load(cert_path)?;
    let transport = transport::Transport::new(local_address).await?;
    let controller = controller::Controller::new(&cm, &transport, cm.get_fabric_id())?;
    let connection = transport.create_connection(device_address).await;
    let c = controller
        .auth_sigma(&connection, device_id, controller_id)
        .await?;
    Ok(c)
}

fn commission(
    controller_id: u64,
    device_address: &str,
    pin: u32,
    local_address: &str,
    device_id: u64,
    cert_path: &str,
) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(async {
        let cm: Arc<dyn certmanager::CertManager> =
            certmanager::FileCertManager::load(cert_path).unwrap();
        let transport = transport::Transport::new(local_address).await.unwrap();
        let controller = controller::Controller::new(&cm, &transport, cm.get_fabric_id()).unwrap();
        let connection = transport.create_connection(device_address).await;
        let con = controller
            .commission(&connection, pin, device_id, controller_id)
            .await
            .unwrap();
        println!("commissioning ok. now list supported clusters (endpoint 0):");
        let resptlv = con.read_request2(0, 0x1d, 1).await.unwrap();
        if let tlv::TlvItemValue::List(l) = resptlv {
            for c in l {
                if let tlv::TlvItemValue::Int(v) = c.value {
                    println!("{:?}", clusters::names::get_cluster_name(v as u32));
                }
            }
        }
    });
}

async fn progress(duration: Duration) {
    tokio::spawn(async move {
        let start_time = time::SystemTime::now();
        while start_time.elapsed().unwrap() < duration {
            println!(
                "remaining time: {:.2}sec",
                (duration - start_time.elapsed().unwrap()).as_secs_f32()
            );
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    });
}

fn discover_cmd(discover: DiscoverCommand, timeout: u64, cert_path: String) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let time = Duration::from_secs(timeout);
    match discover {
        DiscoverCommand::Commissionable {} => runtime.block_on(async {
            progress(time).await;
            let infos = discover::discover_commissionable(time).await.unwrap();
            for info in infos {
                println!("{:#?}", info);
            }
        }),
        DiscoverCommand::Commissioned {} => runtime.block_on(async {
            progress(time).await;
            let infos = discover::discover_commissioned2(time, &None).await.unwrap();
            for info in infos {
                println!("{:#?}", info);
            }
        }),
        DiscoverCommand::Commissioned2 { device_id } => runtime.block_on(async {
            let device_str = if let Some(device_id) = device_id {
                let cm: Arc<dyn certmanager::CertManager> = certmanager::FileCertManager::load(&cert_path).unwrap();
                let fabric = matc::fabric::Fabric::new(cm.get_fabric_id(), 1, &cm.get_ca_public_key().unwrap());
                let c = fabric.compressed().unwrap();
                Some(format!("{}-{:016X}", hex::encode(c).to_uppercase(), device_id))
            } else {
                None
            };
            println!("discovering commissioned devices with device id filter: {:?}", device_str);
            progress(time).await;
            let infos = discover::discover_commissioned2(time, &device_str).await.unwrap();
            for info in infos {
                println!("{:#?}", info);
            }
        }),
    }
}

fn bridged_device_attr_name_from_id(id: u32) -> &'static str {
    match id {
        0x0000 => "DataModelRevision",
        0x0001 => "VendorName",
        0x0002 => "VendorID",
        0x0003 => "ProductName",
        0x0004 => "ProductID",
        0x0005 => "NodeLabel",
        0x0006 => "Location",
        0x0007 => "HardwareVersion",
        0x0008 => "HardwareVersionString",
        0x0009 => "SoftwareVersion",
        0x000A => "SoftwareVersionString",
        0x000B => "ManufacturingDate",
        0x000C => "PartNumber",
        0x000D => "ProductURL",
        0x000E => "ProductLabel",
        0x000F => "SerialNumber",
        0x0010 => "LocalConfigDisabled",
        0x0011 => "Reachable",
        0x0012 => "UniqueID",
        0x0013 => "CapabilityMinima",
        0x0014 => "ProductAppearance",
        0x0015 => "SpecificationVersion",
        0x0016 => "MaxPathsPerInvoke",
        0x0018 => "ConfigurationVersion",
        _ => "Unknown",
    }
}

async fn bridge_info(connection: &mut controller::Connection) {
    let resptlv = connection
        .read_request2(
            0,
            clusters::defs::CLUSTER_ID_DESCRIPTOR,
            clusters::defs::CLUSTER_DESCRIPTOR_ATTR_ID_PARTSLIST,
        )
        .await
        .unwrap();
    if let tlv::TlvItemValue::List(l) = resptlv {
        for part in l {
            if let tlv::TlvItemValue::Int(v) = part.value {
                println!("endpoint {}", v);
                for n in 0..0x18 {
                    let out = connection
                        .read_request2(
                            v as u16,
                            clusters::defs::CLUSTER_ID_BRIDGED_DEVICE_BASIC_INFORMATION,
                            n,
                        )
                        .await;
                    if let Ok(out) = out {
                        println!("  attr 0x{:x} {}: {:?}", n, bridged_device_attr_name_from_id(n), out);
                    }
                }
                let supported_clusters = connection
                    .read_request2(v as u16, clusters::defs::CLUSTER_ID_DESCRIPTOR,
                    clusters::defs::CLUSTER_DESCRIPTOR_ATTR_ID_SERVERLIST)
                    .await
                    .unwrap();
                println!("  Supported clusters:");
                if let tlv::TlvItemValue::List(l) = supported_clusters {
                    for c in l {
                        if let tlv::TlvItemValue::Int(v) = c.value {
                            match clusters::names::get_cluster_name(v as u32) {
                                Some(v) => println!("    {}", v),
                                None => println!(".   unknown cluster - id 0x{:x}", v),
                            }
                        }
                    }
                }
                let taglist = connection
                    .read_request2(v as u16, clusters::defs::CLUSTER_ID_DESCRIPTOR,
                    clusters::defs::CLUSTER_DESCRIPTOR_ATTR_ID_TAGLIST)
                    .await;
                if let Ok(taglist) = taglist {
                    println!("  taglist: {:?}", taglist);
                }
                let devtypes = connection
                    .read_request2(v as u16, clusters::defs::CLUSTER_ID_DESCRIPTOR,
                    clusters::defs::CLUSTER_DESCRIPTOR_ATTR_ID_DEVICETYPELIST)
                    .await;
                if let Ok(tlv::TlvItemValue::List(devtypes)) = devtypes {
                    for c in devtypes {
                            let typ = c.get_int(&[0]);
                            if let Some(typ) = typ {
                                if let Some(name) = clusters::dt_names::get_device_type_name(typ as u32) {
                                    println!("  device type: {} (0x{:x})", name, typ);
                                } else {
                                    println!("  device type: unknown (0x{:x})", typ);
                                }
                            }
                    }
                }
                let parts = connection
                    .read_request2(v as u16, clusters::defs::CLUSTER_ID_DESCRIPTOR,
                    clusters::defs::CLUSTER_DESCRIPTOR_ATTR_ID_PARTSLIST)
                    .await;
                if let Ok(parts) = parts {
                    let mut parts_str = "".to_string();
                    if let tlv::TlvItemValue::List(l) = parts {
                        for c in l {
                            if let tlv::TlvItemValue::Int(v) = c.value {
                                parts_str += &format!("{} ", v);
                            }
                        }
                    }
                    if !parts_str.is_empty() {
                        println!("  parts: {}", parts_str);
                    }
                }
            }
        }
    }
}

async fn print_cluster_attributes(
    connection: &mut controller::Connection,
    endpoint: u16,
    cluster: u32,
) {
    match clusters::names::get_cluster_name(cluster) {
        Some(v) => println!("    {}", v),
        None => println!("    unknown cluster - id 0x{:x}", cluster),
    }
    let attrlist = clusters::codec::get_attribute_list(cluster);
    for attr in attrlist {
        let out = connection.read_request2(endpoint, cluster, attr.0).await;
        if let Ok(out) = out {
            println!(
                "      attr 0x{:x} {}: {}",
                attr.0,
                attr.1,
                clusters::codec::decode_attribute_json(cluster, attr.0, &out)
            );
        } else {
            //println!("      attr 0x{:x} {}: <read error> {:?}", attr.0, attr.1, out);
        }
    }
}
async fn print_endpoint_attributes(connection: &mut controller::Connection, endpoint: u16) {
    let resptlv = connection
        .read_request2(
            endpoint,
            clusters::defs::CLUSTER_ID_DESCRIPTOR,
            clusters::defs::CLUSTER_DESCRIPTOR_ATTR_ID_SERVERLIST,
        )
        .await
        .unwrap();
    println!("  clusters:");
    if let tlv::TlvItemValue::List(l) = resptlv {
        for c in l {
            if let tlv::TlvItemValue::Int(cluster) = c.value {
                print_cluster_attributes(connection, endpoint, cluster as u32).await;
            }
        }
    }
}
async fn all_attributes(connection: &mut controller::Connection) {
    let resptlv = connection
        .read_request2(
            0,
            clusters::defs::CLUSTER_ID_DESCRIPTOR,
            clusters::defs::CLUSTER_DESCRIPTOR_ATTR_ID_PARTSLIST,
        )
        .await
        .unwrap();
    if let tlv::TlvItemValue::List(l) = resptlv {
        for part in l {
            if let tlv::TlvItemValue::Int(v) = part.value {
                println!("endpoint {}", v);
                print_endpoint_attributes(connection, v as u16).await;
            }
        }
    }
    println!("endpoint 0");
    print_endpoint_attributes(connection, 0).await;
}

struct EndpointInfo {
    endpoint: u16,
    device_types: Vec<(u32, String)>,
    label: Option<String>,
    product_name: Option<String>,
    product_label: Option<String>,
    vendor_name: Option<String>,
    reachable: Option<bool>,
    parts: Vec<u16>,
    on_off: Option<bool>,
    level: Option<u64>,
    battery_level: Option<String>,
    temperature: Option<i64>,
    occupancy: Option<u64>,
    illuminance: Option<u64>,
    rooms: Vec<String>,
}

async fn collect_endpoint_info(connection: &mut controller::Connection, endpoint: u16) -> EndpointInfo {
    use clusters::defs::*;
    let mut info = EndpointInfo {
        endpoint,
        device_types: Vec::new(),
        label: None,
        product_name: None,
        product_label: None,
        vendor_name: None,
        reachable: None,
        parts: Vec::new(),
        on_off: None,
        level: None,
        battery_level: None,
        temperature: None,
        occupancy: None,
        illuminance: None,
        rooms: Vec::new(),
    };

    if let Ok(tlv::TlvItemValue::List(lst)) = connection.read_request2(
        endpoint, CLUSTER_ID_DESCRIPTOR, CLUSTER_DESCRIPTOR_ATTR_ID_DEVICETYPELIST,
    ).await {
        for item in &lst {
            if let Some(dt_id) = item.get_int(&[0]) {
                let name = clusters::dt_names::get_device_type_name(dt_id as u32)
                    .unwrap_or("Unknown")
                    .to_string();
                info.device_types.push((dt_id as u32, name));
            }
        }
    }

    if let Ok(tlv::TlvItemValue::List(lst)) = connection.read_request2(
        endpoint, CLUSTER_ID_DESCRIPTOR, CLUSTER_DESCRIPTOR_ATTR_ID_PARTSLIST,
    ).await {
        for item in lst {
            if let tlv::TlvItemValue::Int(v) = item.value {
                info.parts.push(v as u16);
            }
        }
    }

    let server_clusters: Vec<u32> = if let Ok(tlv::TlvItemValue::List(lst)) = connection.read_request2(
        endpoint, CLUSTER_ID_DESCRIPTOR, CLUSTER_DESCRIPTOR_ATTR_ID_SERVERLIST,
    ).await {
        lst.into_iter()
            .filter_map(|item| if let tlv::TlvItemValue::Int(v) = item.value { Some(v as u32) } else { None })
            .collect()
    } else {
        Vec::new()
    };

    if server_clusters.contains(&CLUSTER_ID_BRIDGED_DEVICE_BASIC_INFORMATION) {
        let c = CLUSTER_ID_BRIDGED_DEVICE_BASIC_INFORMATION;
        if let Ok(tlv::TlvItemValue::String(s)) = connection.read_request2(endpoint, c,
            CLUSTER_BRIDGED_DEVICE_BASIC_INFORMATION_ATTR_ID_VENDORNAME).await {
            info.vendor_name = Some(s);
        }
        if let Ok(tlv::TlvItemValue::String(s)) = connection.read_request2(endpoint, c,
            CLUSTER_BRIDGED_DEVICE_BASIC_INFORMATION_ATTR_ID_PRODUCTNAME).await {
            info.product_name = Some(s);
        }
        if let Ok(tlv::TlvItemValue::String(s)) = connection.read_request2(endpoint, c,
            CLUSTER_BRIDGED_DEVICE_BASIC_INFORMATION_ATTR_ID_NODELABEL).await {
            if !s.is_empty() { info.label = Some(s); }
        }
        if let Ok(tlv::TlvItemValue::String(s)) = connection.read_request2(endpoint, c,
            CLUSTER_BRIDGED_DEVICE_BASIC_INFORMATION_ATTR_ID_PRODUCTLABEL).await {
            info.product_label = Some(s);
        }
        if let Ok(tlv::TlvItemValue::Bool(b)) = connection.read_request2(endpoint, c,
            CLUSTER_BRIDGED_DEVICE_BASIC_INFORMATION_ATTR_ID_REACHABLE).await {
            info.reachable = Some(b);
        }
    }

    if server_clusters.contains(&CLUSTER_ID_BASIC_INFORMATION) {
        let c = CLUSTER_ID_BASIC_INFORMATION;
        if info.vendor_name.is_none() {
            if let Ok(tlv::TlvItemValue::String(s)) = connection.read_request2(endpoint, c,
                CLUSTER_BASIC_INFORMATION_ATTR_ID_VENDORNAME).await {
                info.vendor_name = Some(s);
            }
        }
        if info.product_name.is_none() {
            if let Ok(tlv::TlvItemValue::String(s)) = connection.read_request2(endpoint, c,
                CLUSTER_BASIC_INFORMATION_ATTR_ID_PRODUCTNAME).await {
                info.product_name = Some(s);
            }
        }
        if info.label.is_none() {
            if let Ok(tlv::TlvItemValue::String(s)) = connection.read_request2(endpoint, c,
                CLUSTER_BASIC_INFORMATION_ATTR_ID_NODELABEL).await {
                if !s.is_empty() { info.label = Some(s); }
            }
        }
    }

    if server_clusters.contains(&CLUSTER_ID_ON_OFF) {
        if let Ok(tlv::TlvItemValue::Bool(b)) = connection.read_request2(endpoint,
            CLUSTER_ID_ON_OFF, CLUSTER_ON_OFF_ATTR_ID_ONOFF).await {
            info.on_off = Some(b);
        }
    }

    if server_clusters.contains(&CLUSTER_ID_LEVEL_CONTROL) {
        if let Ok(tlv::TlvItemValue::Int(v)) = connection.read_request2(endpoint,
            CLUSTER_ID_LEVEL_CONTROL, CLUSTER_LEVEL_CONTROL_ATTR_ID_CURRENTLEVEL).await {
            info.level = Some(v);
        }
    }

    if server_clusters.contains(&CLUSTER_ID_POWER_SOURCE) {
        let out = connection.read_request2(endpoint,
            CLUSTER_ID_POWER_SOURCE, CLUSTER_POWER_SOURCE_ATTR_ID_BATCHARGELEVEL).await;
        if let Ok(ref val) = out {
            let json = clusters::codec::decode_attribute_json(
                CLUSTER_ID_POWER_SOURCE, CLUSTER_POWER_SOURCE_ATTR_ID_BATCHARGELEVEL, val);
            info.battery_level = Some(json.trim_matches('"').to_string());
        }
    }

    if server_clusters.contains(&CLUSTER_ID_TEMPERATURE_MEASUREMENT) {
        if let Ok(tlv::TlvItemValue::Int(v)) = connection.read_request2(endpoint,
            CLUSTER_ID_TEMPERATURE_MEASUREMENT,
            CLUSTER_TEMPERATURE_MEASUREMENT_ATTR_ID_MEASUREDVALUE).await {
            info.temperature = Some(v as i64);
        }
    }

    if server_clusters.contains(&CLUSTER_ID_OCCUPANCY_SENSING) {
        if let Ok(tlv::TlvItemValue::Int(v)) = connection.read_request2(endpoint,
            CLUSTER_ID_OCCUPANCY_SENSING, CLUSTER_OCCUPANCY_SENSING_ATTR_ID_OCCUPANCY).await {
            info.occupancy = Some(v);
        }
    }

    if server_clusters.contains(&CLUSTER_ID_ILLUMINANCE_MEASUREMENT) {
        if let Ok(tlv::TlvItemValue::Int(v)) = connection.read_request2(endpoint,
            CLUSTER_ID_ILLUMINANCE_MEASUREMENT,
            CLUSTER_ILLUMINANCE_MEASUREMENT_ATTR_ID_MEASUREDVALUE).await {
            info.illuminance = Some(v);
        }
    }

    info
}

async fn collect_rooms(connection: &mut controller::Connection) -> Vec<(String, Vec<u16>)> {
    let out = connection.read_request2(
        1,
        clusters::defs::CLUSTER_ID_ACTIONS,
        clusters::defs::CLUSTER_ACTIONS_ATTR_ID_ENDPOINTLISTS,
    ).await;
    if let Ok(ref val) = out {
        let json_str = clusters::codec::decode_attribute_json(
            clusters::defs::CLUSTER_ID_ACTIONS,
            clusters::defs::CLUSTER_ACTIONS_ATTR_ID_ENDPOINTLISTS,
            val,
        );
        if let Ok(arr) = serde_json::from_str::<serde_json::Value>(&json_str) {
            if let Some(arr) = arr.as_array() {
                return arr.iter().filter_map(|item| {
                    let name = item.get("name")?.as_str()?.to_string();
                    let endpoints: Vec<u16> = item.get("endpoints")?
                        .as_array()?
                        .iter()
                        .filter_map(|v| v.as_u64().map(|n| n as u16))
                        .collect();
                    Some((name, endpoints))
                }).collect();
            }
        }
    }
    Vec::new()
}

fn format_endpoint_summary(info: &EndpointInfo) -> String {
    let mut segments: Vec<String> = Vec::new();

    segments.push(format!("ep{:<3}", info.endpoint));

    if let Some(ref label) = info.label {
        segments.push(format!("\"{}\"", label));
    }

    // Primary device type: skip Bridged Node (0x13) and Root Node (0x16)
    let primary_dt = info.device_types.iter()
        .find(|(id, _)| *id != 0x13 && *id != 0x16)
        .or_else(|| info.device_types.first());
    if let Some((_, name)) = primary_dt {
        segments.push(name.clone());
    }

    let product = info.product_label.as_deref().or(info.product_name.as_deref());
    let vendor = info.vendor_name.as_deref();
    match (product, vendor) {
        (Some(p), Some(v)) => segments.push(format!("{} ({})", p, v)),
        (Some(p), None) => segments.push(p.to_string()),
        _ => {}
    }

    if let Some(on) = info.on_off {
        segments.push(if on { "ON".to_string() } else { "off".to_string() });
    }
    if let Some(lv) = info.level {
        segments.push(format!("lv:{}", lv));
    }
    if let Some(ref bat) = info.battery_level {
        segments.push(format!("bat:{}", bat));
    }
    if let Some(temp) = info.temperature {
        segments.push(format!("{:.1}C", temp as f32 / 100.0));
    }
    if let Some(occ) = info.occupancy {
        segments.push(format!("occ:{}", occ));
    }
    if let Some(lux) = info.illuminance {
        segments.push(format!("lux:{}", lux));
    }

    if !info.rooms.is_empty() {
        segments.push(format!("[{}]", info.rooms.join(", ")));
    }

    if info.reachable == Some(false) {
        segments.push("!unreachable".to_string());
    }

    segments.join("  ")
}

fn print_endpoint_tree(
    infos: &std::collections::HashMap<u16, EndpointInfo>,
    children_map: &std::collections::HashMap<u16, Vec<u16>>,
    endpoint: u16,
    node_prefix: &str,
    children_prefix: &str,
) {
    if let Some(info) = infos.get(&endpoint) {
        println!("{}{}", node_prefix, format_endpoint_summary(info));
        if let Some(children) = children_map.get(&endpoint) {
            let n = children.len();
            for (i, &child) in children.iter().enumerate() {
                let is_last = i == n - 1;
                let child_node_prefix = format!("{}+-- ", children_prefix);
                let child_children_prefix = if is_last {
                    format!("{}    ", children_prefix)
                } else {
                    format!("{}|   ", children_prefix)
                };
                print_endpoint_tree(infos, children_map, child, &child_node_prefix, &child_children_prefix);
            }
        }
    }
}

async fn list_devices(connection: &mut controller::Connection) {
    use std::collections::HashMap;
    use clusters::defs::*;

    let all_eps_tlv = connection.read_request2(
        0, CLUSTER_ID_DESCRIPTOR, CLUSTER_DESCRIPTOR_ATTR_ID_PARTSLIST,
    ).await;
    let mut all_endpoints: Vec<u16> = vec![0];
    if let Ok(tlv::TlvItemValue::List(lst)) = all_eps_tlv {
        for item in lst {
            if let tlv::TlvItemValue::Int(v) = item.value {
                all_endpoints.push(v as u16);
            }
        }
    }

    let mut infos: HashMap<u16, EndpointInfo> = HashMap::new();
    for ep in &all_endpoints {
        let info = collect_endpoint_info(connection, *ep).await;
        infos.insert(*ep, info);
    }

    let rooms = collect_rooms(connection).await;

    let mut ep_to_rooms: HashMap<u16, Vec<String>> = HashMap::new();
    for (room_name, eps) in &rooms {
        for &ep in eps {
            ep_to_rooms.entry(ep).or_default().push(room_name.clone());
        }
    }
    for info in infos.values_mut() {
        if let Some(room_list) = ep_to_rooms.get(&info.endpoint) {
            info.rooms = room_list.clone();
        }
    }

    // Print bridge info from ep0
    let sw_ver = connection.read_request2(0, CLUSTER_ID_BASIC_INFORMATION,
        CLUSTER_BASIC_INFORMATION_ATTR_ID_SOFTWAREVERSIONSTRING).await;
    let serial = connection.read_request2(0, CLUSTER_ID_BASIC_INFORMATION,
        CLUSTER_BASIC_INFORMATION_ATTR_ID_SERIALNUMBER).await;
    let sw_str = if let Ok(tlv::TlvItemValue::String(s)) = sw_ver { s } else { String::new() };
    let serial_str = if let Ok(tlv::TlvItemValue::String(s)) = serial { s } else { String::new() };

    let bridge_label = infos.get(&0).and_then(|i| i.label.clone());
    let bridge_product = infos.get(&0).and_then(|i| i.product_name.clone());
    let bridge_vendor = infos.get(&0).and_then(|i| i.vendor_name.clone());
    let bridge_display = match (bridge_label, bridge_product, bridge_vendor) {
        (Some(label), Some(product), Some(vendor)) => format!("{} ({}) by {}", label, product, vendor),
        (Some(label), Some(product), None) => format!("{} ({})", label, product),
        (Some(label), None, _) => label,
        (None, Some(product), Some(vendor)) => format!("{} by {}", product, vendor),
        (None, Some(product), None) => product,
        _ => "Unknown".to_string(),
    };
    print!("Bridge: {}", bridge_display);
    if !sw_str.is_empty() { print!("  sw {}", sw_str); }
    if !serial_str.is_empty() { print!("  serial {}", serial_str); }
    println!();

    // Print rooms
    if !rooms.is_empty() {
        println!("\nRooms:");
        let max_name_len = rooms.iter().map(|(n, _)| n.len()).max().unwrap_or(0);
        for (room_name, eps) in &rooms {
            let device_names: Vec<String> = eps.iter().filter_map(|ep| {
                let info = infos.get(ep)?;
                info.label.clone()
                    .or_else(|| info.product_label.clone())
                    .or_else(|| info.product_name.clone())
            }).collect();
            println!("  {:<width$}  {}", room_name, device_names.join(", "), width = max_name_len);
        }
    }

    // Build direct parent map: for each endpoint, find its most specific parent
    // (the parent that is itself a child of another ancestor)
    let mut all_parents: HashMap<u16, Vec<u16>> = HashMap::new();
    for (&ep, info) in &infos {
        for &part in &info.parts {
            all_parents.entry(part).or_default().push(ep);
        }
    }
    let mut direct_parent: HashMap<u16, u16> = HashMap::new();
    for (&ep, parents) in &all_parents {
        // Pick the deepest ancestor: the parent contained by the most other parents in the set
        let best = parents.iter().max_by_key(|&&p| {
            parents.iter().filter(|&&q| q != p && infos.get(&q).is_some_and(|qi| qi.parts.contains(&p))).count()
        }).copied();
        if let Some(b) = best {
            direct_parent.insert(ep, b);
        }
    }

    let mut children_map: HashMap<u16, Vec<u16>> = HashMap::new();
    for (&ep, &parent) in &direct_parent {
        children_map.entry(parent).or_default().push(ep);
    }
    for children in children_map.values_mut() {
        children.sort();
    }

    let mut roots: Vec<u16> = all_endpoints.iter()
        .filter(|&&ep| !direct_parent.contains_key(&ep))
        .copied()
        .collect();
    roots.sort();

    println!("\nDevices:");
    for &root in &roots {
        print_endpoint_tree(&infos, &children_map, root, "  ", "  ");
    }
}

fn command_cmd(
    command: CommandCommand,
    local_address: &str,
    device_address: &str,
    controller_id: u64,
    device_id: u64,
    cert_path: &str,
    endpoint: u16,
) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(async {
        {
        let mut connection =
            create_connection(local_address, device_address, device_id, controller_id, cert_path)
                .await
                .unwrap();

        match command {
            CommandCommand::Read {
                endpoint,
                cluster,
                attr,
            } => {
                let res = connection
                    .read_request(endpoint, cluster, attr)
                    .await
                    .unwrap();
                res.tlv.dump(1);
            }
            CommandCommand::InvokeCommandOn {} => {
                let res = connection.invoke_request(endpoint, 0x6, 1, &[]).await.unwrap();
                res.tlv.dump(1);
            }
            CommandCommand::InvokeCommandOff {} => {
                let res = connection.invoke_request(endpoint, 0x6, 0, &[]).await.unwrap();
                res.tlv.dump(1);
            }
            CommandCommand::InvokeCommandMoveToLevel { level } => {
                let tlv = tlv::TlvItemEnc {
                    tag: 0,
                    value: tlv::TlvItemValueEnc::StructInvisible(vec![
                        (0, tlv::TlvItemValueEnc::UInt8(level)).into(),
                        (1, tlv::TlvItemValueEnc::UInt16(10)).into(), // transition time
                        (2, tlv::TlvItemValueEnc::UInt8(0)).into(), // options mask
                        (3, tlv::TlvItemValueEnc::UInt8(0)).into(), // options override
                    ]),
                }
                .encode()
                .unwrap();
                let res = connection
                    .invoke_request(
                        endpoint,
                        clusters::defs::CLUSTER_ID_LEVEL_CONTROL,
                        clusters::defs::CLUSTER_LEVEL_CONTROL_CMD_ID_MOVETOLEVEL,
                        &tlv,
                    )
                    .await
                    .unwrap();
                res.tlv.dump(1);
            }
            CommandCommand::InvokeCommandMoveToHue { hue } => {
                let tlv = tlv::TlvItemEnc {
                    tag: 0,
                    value: tlv::TlvItemValueEnc::StructInvisible(vec![
                        (0, tlv::TlvItemValueEnc::UInt8(hue)).into(),
                        (1, tlv::TlvItemValueEnc::UInt8(0)).into(), // direction
                        (2, tlv::TlvItemValueEnc::UInt16(10)).into(), // time
                        (3, tlv::TlvItemValueEnc::UInt8(0)).into(), // options mask
                        (4, tlv::TlvItemValueEnc::UInt8(0)).into(), // options override
                    ]),
                }
                .encode()
                .unwrap();
                let res = connection
                    .invoke_request(
                        endpoint,
                        clusters::defs::CLUSTER_ID_COLOR_CONTROL,
                        clusters::defs::CLUSTER_COLOR_CONTROL_CMD_ID_MOVETOHUE,
                        &tlv,
                    )
                    .await
                    .unwrap();
                res.tlv.dump(1);
            }
            CommandCommand::InvokeCommandUpdateFabricLabel { label } => {
                let tlv = tlv::TlvItemEnc {
                    tag: 0,
                    value: tlv::TlvItemValueEnc::String(label),
                }
                .encode()
                .unwrap();
                let res = connection.invoke_request(0, 0x3e, 9, &tlv).await.unwrap();
                res.tlv.dump(1);
            }
            CommandCommand::InvokeCommandRemoveFabric { index } => {
                let tlv = tlv::TlvItemEnc {
                    tag: 0,
                    value: tlv::TlvItemValueEnc::UInt8(index),
                }
                .encode()
                .unwrap();
                let res = connection.invoke_request(0, 0x3e, 0xa, &tlv).await.unwrap();
                res.tlv.dump(1);
            }
            CommandCommand::ListSupportedClusters { endpoint } => {
                let resptlv = connection.read_request2(endpoint, 0x1d, 1).await.unwrap();
                if let tlv::TlvItemValue::List(l) = resptlv {
                    for c in l {
                        if let tlv::TlvItemValue::Int(v) = c.value {
                            match clusters::names::get_cluster_name(v as u32) {
                                Some(v) => println!("{}", v),
                                None => println!("unknown cluster - id 0x{:x}", v),
                            }
                        }
                    }
                }
            }
            CommandCommand::ListSupportedClusters2 { endpoint } => {
                let resptlv = connection.read_request(endpoint, 0x1d, 1).await.unwrap();
                let r = resptlv.tlv.get(&[1]).unwrap();
                if let tlv::TlvItemValue::List(l) = r {
                    for r in l {
                        let v = r.get(&[1, 2]);
                        if let Some(tlv::TlvItemValue::Int(v)) = v {
                            match clusters::names::get_cluster_name(*v as u32) {
                                Some(v) => println!("{}", v),
                                None => println!("unknown cluster - id 0x{:x}", v),
                            }
                        }
                    }
                }
            }
            CommandCommand::ListParts {} => {
                let resptlv = connection
                    .read_request2(
                        0,
                        clusters::defs::CLUSTER_ID_DESCRIPTOR,
                        clusters::defs::CLUSTER_DESCRIPTOR_ATTR_ID_PARTSLIST,
                    )
                    .await
                    .unwrap();
                println!("{:?}", resptlv);
                if let tlv::TlvItemValue::List(l) = resptlv {
                    for c in l {
                        if let tlv::TlvItemValue::Int(v) = c.value {
                            println!("{}", v);
                        }
                    }
                }
            }
            CommandCommand::ListBridgedDevices {} => {
                bridge_info(&mut connection).await;
            }
            CommandCommand::ListAttributes {} => {
                all_attributes(&mut connection).await;
            }
            CommandCommand::ListDevices {} => {
                list_devices(&mut connection).await;
            }
            CommandCommand::StartCommissioning { pin, iterations, discriminator, timeout } => {
                let mut salt = [0; 32];
                rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);
                let key = &matc::controller::pin_to_passcode(pin).unwrap();
                let data = matc::spake2p::Engine::create_passcode_verifier(key, &salt, iterations);
                let tlv = tlv::TlvItemEnc {
                            tag: 0,
                            value: tlv::TlvItemValueEnc::StructInvisible(vec![
                                    (0, tlv::TlvItemValueEnc::UInt16(timeout)).into(),
                                    (1, tlv::TlvItemValueEnc::OctetString(data)).into(),
                                    (2, tlv::TlvItemValueEnc::UInt16(discriminator)).into(),
                                    (3, tlv::TlvItemValueEnc::UInt32(iterations)).into(),
                                    (4, tlv::TlvItemValueEnc::OctetString(salt.to_vec())).into(),
                            ]),
                        }
                        .encode()
                        .unwrap();
                let res = connection.invoke_request_timed(0, clusters::defs::CLUSTER_ID_ADMINISTRATOR_COMMISSIONING, clusters::defs::CLUSTER_ADMINISTRATOR_COMMISSIONING_CMD_ID_OPENCOMMISSIONINGWINDOW, &tlv, 6000).await.unwrap();
                log::debug!("start commissioning response: {:?}", res);
                if res.protocol_header.protocol_id != messages::ProtocolMessageHeader::PROTOCOL_ID_INTERACTION
                    || res.protocol_header.opcode != messages::ProtocolMessageHeader::INTERACTION_OPCODE_INVOKE_RESP
                {
                    panic!("unexpected response {:?}", res);
                }
                let (_common_status, status) = messages::parse_im_invoke_resp(&res.tlv).unwrap();
                match status {
                    0 => log::info!("start commissioning status: success"),
                    2 => log::info!("start commissioning status: busy(2)"),
                    3 => log::info!("start commissioning status: pake error(3)"),
                    4 => log::info!("start commissioning status: window not open(4)"),
                    _ => log::info!("start commissioning status: {}", status),
                }
            },
            CommandCommand::MonitorDoorState{} => {
                fn decode_door_change_state_event(tlv: TlvItem) {
                    let tlv_stat = tlv.get(&[2]);
                    if let Some(tlv_stat) =  tlv_stat {
                        if let tlv::TlvItemValue::List(lst) = tlv_stat {
                            for item in lst {
                                let par = item.get(&[1, 7]);
                                if let Some(par) = par {
                                    println!("status: {:?}", clusters::codec::door_lock::decode_door_state_change_event(par));
                                }
                            }
                        } else {
                            println!("no events in report data");
                        }
                    }
                }
                let res = connection.im_subscribe_request(1, 0x101, 1).await.unwrap();
                if res.protocol_header.opcode != messages::ProtocolMessageHeader::INTERACTION_OPCODE_REPORT_DATA {
                    log::warn!("unexpected response opcode 0x{:x}", res.protocol_header.opcode);
                } else {
                    decode_door_change_state_event(res.tlv.clone());
                }
                connection.im_status_response(res.protocol_header.exchange_id, 1 | 2, res.message_header.message_counter).await.unwrap();
                loop {
                    let ev = connection.recv_event().await.unwrap();
                    match ev.protocol_header.opcode {
                        messages::ProtocolMessageHeader::INTERACTION_OPCODE_REPORT_DATA => {
                            println!("this is Event/Report Data {}", ev.protocol_header.exchange_id);
                            decode_door_change_state_event(ev.tlv.clone());
                            connection.im_status_response(ev.protocol_header.exchange_id, 2, ev.message_header.message_counter).await.unwrap();
                            println!("sent status response");
                        }
                        messages::ProtocolMessageHeader::INTERACTION_OPCODE_SUBSCRIBE_RESP => {
                            println!("this is Subscribe Response {}", ev.protocol_header.exchange_id);
                        }
                        _ => {
                            println!("unhandled event opcode 0x{:x}", ev.protocol_header.opcode);
                        }
                    }
                }
            }
            CommandCommand::Test2{} => {
                let tlv = clusters::codec::door_lock::encode_get_user(1).unwrap();
                let res = connection.invoke_request(1, CLUSTER_ID_DOOR_LOCK, CLUSTER_DOOR_LOCK_CMD_ID_GETUSER, &tlv).await.unwrap();
                let tlv = res.tlv.get(&[1, 0, 0, 1]).unwrap();
                let dec = clusters::codec::door_lock::decode_get_user_response(tlv).unwrap();
                println!("decoded get user response: {:?}", dec);

            }
        }
        }
    });
}

fn main() {
    let cli = Cli::parse();

    let log_level = {
        if cli.verbose {
            log::LevelFilter::Trace
        } else {
            log::LevelFilter::Error
        }
    };
    env_logger::Builder::new()
        .parse_default_env()
        .target(env_logger::Target::Stdout)
        .filter_level(log_level)
        .format_line_number(true)
        .format_file(true)
        .format_timestamp(Some(env_logger::TimestampPrecision::Millis))
        .init();

    let cert_path = cli.cert_path;

    match cli.command {
        Commands::Commission {
            controller_id,
            device_address,
            pin,
            local_address,
            device_id,
        } => {
            commission(
                controller_id,
                &device_address,
                pin,
                &local_address,
                device_id,
                &cert_path,
            );
        }
        Commands::CaBootstrap { fabric_id } => {
            let cm = FileCertManager::new(fabric_id, &cert_path);
            cm.bootstrap().unwrap();
        }
        Commands::CaCreateController { controller_id } => {
            let cm = FileCertManager::load(&cert_path).unwrap();
            cm.create_user(controller_id).unwrap();
        }
        Commands::ListSupportedClusters {
            local_address,
            device_address,
            controller_id,
            device_id,
            endpoint,
        } => {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            runtime.block_on(async {
                let connection = create_connection(
                    &local_address,
                    &device_address,
                    device_id,
                    controller_id,
                    &cert_path,
                )
                .await
                .unwrap();
                let resptlv = connection.read_request2(endpoint, 0x1d, 1).await.unwrap();
                if let tlv::TlvItemValue::List(l) = resptlv {
                    for c in l {
                        if let tlv::TlvItemValue::Int(v) = c.value {
                            match clusters::names::get_cluster_name(v as u32) {
                                Some(v) => println!("{}", v),
                                None => println!("unknown cluster - id 0x{:x}", v),
                            }
                        }
                    }
                }
            });
        }
        /*Commands::ListFabrics {
            fabric_id,
            local_address,
            device_address,
            controller_id,
            device_id } => {
                let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            runtime.block_on(async {
                let cm: Arc<dyn certmanager::CertManager> = certmanager::FileCertManager::new(fabric_id, CERT_PATH);
                let transport = transport::Transport::new(&local_address).await.unwrap();
                let controller = controller::Controller::new(&cm, &transport, fabric_id);
                let connection = transport.create_connection(&device_address).await;
                let mut connection = controller.auth_sigma(&connection, device_id, controller_id).await.unwrap();
                let response = connection.read_request(
                    0,
                    matc::clusters::OperationalCredentialCluster::CLUSTER_ID_OPERATIONAL_CREDENTIALS,
                    matc::clusters::OperationalCredentialCluster::ATTRIB_ID_FABRICS).await.unwrap();
                let resplist = response.tlv.get(&[1,0,1,2]).unwrap();
                if let tlv::TlvItemValue::List(l) = resplist {
                    for c in l {
                        println!("{:?}", matc::clusters::OperationalCredentialCluster::FabricDescriptorStruct::decode(c))
                    }
                }
            });
        },*/
        Commands::Command {
            command,
            local_address,
            device_address,
            controller_id,
            device_id,
            endpoint,
        } => {
            command_cmd(
                command,
                &local_address,
                &device_address,
                controller_id,
                device_id,
                &cert_path,
                endpoint,
            );
        }
        Commands::Discover { discover, timeout } => {
            discover_cmd(discover, timeout, cert_path);
        }
        Commands::DecodeManualPairingCode { code } => {
            let res = onboarding::decode_manual_pairing_code(&code).unwrap();
            println!(
                "discriminator: {}\npasscode: {}",
                res.discriminator, res.passcode
            )
        }
    }
}
