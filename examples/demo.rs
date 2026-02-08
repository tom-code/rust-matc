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

fn discover_cmd(discover: DiscoverCommand, timeout: u64) {
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
            let infos = discover::discover_commissioned(time).await.unwrap();
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
            discover_cmd(discover, timeout);
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
