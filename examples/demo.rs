use std::sync::Arc;

use anyhow::Result;
use clap::{Parser, Subcommand};
use matc::{
    certmanager::{self, FileCertManager},
    controller, tlv, transport,
};

const DEFAULT_FABRIC: u64 = 0x110;
const DEFAULT_LOCAL_ADDRESS: &str = "0.0.0.0:5555";
const CERT_PATH: &str = "./pem";

const DEFAULT_DEVICE_ADDRESS: &str = "192.168.5.108:5540";
#[derive(Parser, Debug)]
#[command()]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Commission device
    Commission {
        #[clap(long)]
        #[arg(default_value_t = DEFAULT_FABRIC)]
        fabric_id: u64,

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
        #[arg(default_value_t = DEFAULT_FABRIC)]
        fabric_id: u64,

        #[clap(long)]
        #[arg(default_value_t=DEFAULT_LOCAL_ADDRESS.to_string())]
        local_address: String,

        device_address: String,
        controller_id: u64,
        device_id: u64,
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
    /// Create key and certificate for controller
    CaCreateController {
        #[clap(long)]
        #[arg(default_value_t = DEFAULT_FABRIC)]
        fabric_id: u64,
        controller_id: u64,
    },
    Command {
        #[clap(long)]
        #[arg(global = true, default_value_t = DEFAULT_FABRIC)]
        fabric_id: u64,

        #[clap(long)]
        #[arg(global = true, default_value_t = DEFAULT_LOCAL_ADDRESS.to_string())]
        local_address: String,

        #[clap(long)]
        #[arg(default_value_t = DEFAULT_DEVICE_ADDRESS.to_string())]
        device_address: String,

        #[clap(long)]
        #[arg(default_value_t = 100)]
        controller_id: u64,

        #[clap(long)]
        #[arg(default_value_t = 300)]
        device_id: u64,

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
    InvokeCommandUpdateFabricLabel {
        label: String,
    },
}

async fn create_connection(
    fabric_id: u64,
    local_address: &str,
    device_address: &str,
    device_id: u64,
    controller_id: u64,
) -> Result<controller::Connection> {
    let cm: Arc<dyn certmanager::CertManager> =
        certmanager::FileCertManager::new(fabric_id, CERT_PATH);
    let transport = transport::Transport::new(local_address).await?;
    let controller = controller::Controller::new(&cm, &transport, fabric_id);
    let connection = transport.create_connection(device_address).await;
    let c = controller
        .auth_sigma(&connection, device_id, controller_id)
        .await?;
    Ok(c)
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Commission {
            controller_id,
            device_address,
            pin,
            fabric_id,
            local_address,
            device_id,
        } => {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            runtime.block_on(async {
                let cm: Arc<dyn certmanager::CertManager> =
                    certmanager::FileCertManager::new(fabric_id, CERT_PATH);
                let transport = transport::Transport::new(&local_address).await.unwrap();
                let controller = controller::Controller::new(&cm, &transport, fabric_id);
                let connection = transport.create_connection(&device_address).await;
                controller
                    .commission(&connection, pin, device_id, controller_id)
                    .await
                    .unwrap();
            });
        }
        Commands::CaBootstrap { fabric_id } => {
            let cm = FileCertManager::new(fabric_id, CERT_PATH);
            cm.bootstrap().unwrap();
        }
        Commands::CaCreateController {
            fabric_id,
            controller_id,
        } => {
            let cm = FileCertManager::new(fabric_id, CERT_PATH);
            cm.create_user(controller_id).unwrap();
        }
        Commands::ListSupportedClusters {
            fabric_id,
            local_address,
            device_address,
            controller_id,
            device_id,
        } => {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            runtime.block_on(async {
                let mut connection = create_connection(
                    fabric_id,
                    &local_address,
                    &device_address,
                    device_id,
                    controller_id,
                )
                .await
                .unwrap();
                let resptlv = connection.read_request2(0, 0x1d, 1).await.unwrap();
                if let tlv::TlvItemValue::List(l) = resptlv {
                    for c in l {
                        if let tlv::TlvItemValue::Int(v) = c.value {
                            println!("{}", v)
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
            fabric_id,
            local_address,
            device_address,
            controller_id,
            device_id,
        } => {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            runtime.block_on(async {
                let mut connection = create_connection(
                    fabric_id,
                    &local_address,
                    &device_address,
                    device_id,
                    controller_id,
                )
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
                        let res = connection.invoke_request(1, 0x6, 1, &[]).await.unwrap();
                        res.tlv.dump(1);
                    }

                    CommandCommand::InvokeCommandOff {} => {
                        let res = connection.invoke_request(1, 0x6, 0, &[]).await.unwrap();
                        res.tlv.dump(1);
                    }
                    CommandCommand::InvokeCommandMoveToLevel { level } => {
                        let tlv = tlv::TlvItemEnc {
                            tag: 0,
                            value: tlv::TlvItemValueEnc::UInt8(level),
                        }
                        .encode()
                        .unwrap();
                        let res = connection.invoke_request(1, 0x8, 0, &tlv).await.unwrap();
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
                }
            });
        }
    }
}
