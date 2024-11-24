


use clap::{Parser, Subcommand, ValueEnum};
use anyhow::Result;


#[path="../cert.rs"]
mod cert;

#[path="../asn1.rs"]
mod asn1;

#[path="../cryptoutil.rs"]
mod cryptoutil;




fn ca_create() -> Result<()>{
    std::fs::create_dir("./pem2")?;

    let secret_key = p256::SecretKey::random(&mut rand::thread_rng());
    let data = cryptoutil::secret_key_to_rfc5915(&secret_key)?;
    let pem = pem::Pem::new("EC PRIVATE KEY", data);
    std::fs::write("./pem2/ca-private.pem", pem::encode(&pem).as_bytes())?;
    let node_public_key = secret_key.public_key().to_sec1_bytes();

    let x509 = cert::encode_x509(&node_public_key, 1, 0x110, 1, &secret_key, true)?;
    cryptoutil::write_pem("CERTIFICATE", &x509, "./pem2/ca-cert.pem")?;
    Ok(())
}

fn controller_create() -> Result<()>{
    let ca_private = cryptoutil::read_private_key_from_pem("./pem2/ca-private.pem")?;
    let secret_key = p256::SecretKey::random(&mut rand::thread_rng());
    let data = cryptoutil::secret_key_to_rfc5915(&secret_key)?;
    let pem = pem::Pem::new("EC PRIVATE KEY", data);
    std::fs::write("./pem2/100-private.pem", pem::encode(&pem).as_bytes())?;
    let node_public_key = secret_key.public_key().to_sec1_bytes();

    let x509 = cert::encode_x509(&node_public_key, 100, 0x110, 1, &ca_private, false)?;
    cryptoutil::write_pem("CERTIFICATE", &x509, "./pem2/100-cert.pem")?;
    Ok(())
}


#[derive(Parser, Debug)]
#[command()]
struct Cli {    
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    CaCreate {

    },
}
fn main() {
    let cli = Cli::parse();
    println!("{:?}", cli);
    match cli.command {
        Commands::CaCreate {  } => {
            ca_create().unwrap();
            controller_create().unwrap();
        }
    }
}