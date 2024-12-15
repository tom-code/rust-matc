use std::sync::Arc;

use clap::{Parser, Subcommand};
use matc::{certmanager::{self, FileCertManager}, controller, tlv::TlvItemValue, transport};


const DEFAULT_FABRIC: u64 = 0x110;
const DEFAULT_LOCAL_ADDRESS: &str = "0.0.0.0:5555";
const CERT_PATH: &str = "./pem";

#[derive(Parser, Debug)]
#[command()]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
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
    CaBootstrap {
        #[clap(long)]
        #[arg(default_value_t = DEFAULT_FABRIC)]
        fabric_id: u64,
    },
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
        #[arg(global = true, default_value_t=DEFAULT_LOCAL_ADDRESS.to_string())]
        local_address: String,

        #[command(subcommand)]
        command: CommandCommand,
    }
}

#[derive(Subcommand, Debug)]
enum CommandCommand {
    Read {
        device_address: String,
        controller_id: u64,
        device_id: u64,
    },
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
                let cm: Arc<dyn certmanager::CertManager> = certmanager::FileCertManager::new(fabric_id, CERT_PATH);
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
        },
        Commands::CaCreateController { fabric_id, controller_id } => {
            let cm = FileCertManager::new(fabric_id, CERT_PATH);
            cm.create_user(controller_id).unwrap();
        },
        Commands::ListSupportedClusters {
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
                let response = connection.read_request(0, 0x1d, 1).await.unwrap();
                let resplist = response.tlv.get(&[1,0,1,2]).unwrap();
                if let TlvItemValue::List(l) = resplist {
                    for c in l {
                        if let TlvItemValue::Int(v) = c.value {
                            println!("{}", v)
                        }
                    }
                }
            });
        },
        Commands::Command { command, fabric_id, local_address} => {
            match command {
                CommandCommand::Read { device_address, controller_id, device_id  } => todo!(),
            }
        },
    }
}
