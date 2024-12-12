use anyhow::Result;
use clap::{Parser, Subcommand};

use matc::certmanager::{CertManager, FileCertManager};

fn ca_create() -> Result<()> {
    let cm = FileCertManager::new(0x110, "./pem2");
    cm.bootstrap()?;
    cm.create_user(100)
}

#[derive(Parser, Debug)]
#[command()]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    CaCreate {},
}
fn main() {
    let cli = Cli::parse();
    println!("{:?}", cli);
    match cli.command {
        Commands::CaCreate {} => {
            ca_create().unwrap();
        }
    }
}
