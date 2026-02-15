//! Simple utility to discover Matter devices on the local network using mDNS.

use std::{collections::HashMap, time::Duration};
use anyhow::Result;
use clap::Parser;

#[derive(Parser, Debug)]
struct Cli {
    #[clap(long)]
    #[arg(default_value_t = false)]
    verbose: bool,

    #[clap(long)]
    #[arg(default_value_t = false)]
    compact: bool,
}


async fn print_service(target: &str, mdns: &matc::mdns2::MdnsService) -> Result<()> {
    log::debug!("PTR record: {}", target);
    let txt_recors = mdns.lookup(target, matc::mdns::TYPE_TXT).await;
    for txt_rr in txt_recors {
        log::debug!(". TXT record: {:?}", matc::discover::parse_txt_records(&txt_rr.rdata));
    }
    let srv_records = mdns.lookup(target, matc::mdns::TYPE_SRV).await;
    for srv_rr in srv_records {
        log::debug!(". SRV record: {:?}", srv_rr.target);
        let srv_target = match srv_rr.data {
            matc::mdns::RRData::SRV { ref target, .. } => target,
            _ => continue,
        };
        let a_records = mdns.lookup(srv_target, matc::mdns::TYPE_A).await;
        for a_rr in a_records {
            let ip = match a_rr.data {
                matc::mdns::RRData::A(ip) => ip,
                _ => continue,
            };
            log::debug!(".. A record: {}", ip);
        }
        let aaaa_records = mdns.lookup(srv_target, matc::mdns::TYPE_AAAA).await;
        for aaaa_rr in aaaa_records {
            let ip = match aaaa_rr.data {
                matc::mdns::RRData::AAAA(ip) => ip,
                _ => continue,
            };
            log::debug!(".. AAAA record: {}", ip);
        }
        let mi = matc::discover::extract_matter_info(target, mdns).await?;
        println!("{:#?}", mi);
    }
    Ok(())
}

/*async fn request_missing_info(target: &str, mdns: &matc::mdns2::MdnsService) {
    //mdns.active_lookup(target, matc::mdns::TYPE_TXT).await;
    mdns.active_lookup(target, matc::mdns::TYPE_SRV).await;
    let txt_recors = mdns.lookup(target, matc::mdns::TYPE_TXT).await;
    if txt_recors.is_empty() {
        log::debug!("No TXT record found for {}, sending active query", target);
        mdns.active_lookup(target, matc::mdns::TYPE_TXT).await;
    }
    
    let srv_records = mdns.lookup(target, matc::mdns::TYPE_SRV).await;
    if srv_records.is_empty() {
        log::debug!("No SRV record found for {}, sending active query", target);
        mdns.active_lookup(target, matc::mdns::TYPE_SRV).await;
        return;
    }
    for srv_rr in srv_records {
        log::debug!(". SRV record: {:?}", srv_rr.target);
        let srv_target = match srv_rr.data {
            matc::mdns::RRData::SRV { ref target, .. } => target,
            _ => continue,
        };
        let a_records = mdns.lookup(srv_target, matc::mdns::TYPE_A).await;
        let aaaa_records = mdns.lookup(srv_target, matc::mdns::TYPE_AAAA).await;
        if a_records.is_empty() && aaaa_records.is_empty() {
            log::debug!("No A/AAAA record found for {}, sending active query", srv_target);
            mdns.active_lookup(srv_target, matc::mdns::TYPE_A).await;
            mdns.active_lookup(srv_target, matc::mdns::TYPE_AAAA).await;
        }
    }
}*/

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let log_level = if cli.verbose { log::LevelFilter::Trace } else { log::LevelFilter::Error };

    env_logger::Builder::new()
        .parse_default_env()
        .target(env_logger::Target::Stdout)
        .filter_level(log_level)
        .format_line_number(true)
        .format_file(true)
        .format_timestamp(Some(env_logger::TimestampPrecision::Millis))
        .init();

    let (mdns, mut receiver) = matc::mdns2::MdnsService::new().await.unwrap();
    mdns.add_query("_matter._tcp.local", 0xff, Duration::from_secs(10)).await;
    mdns.add_query("_matterc._udp.local", 0xff, Duration::from_secs(10)).await;

    let mut cache = HashMap::new();

    while let Some(dns) = receiver.recv().await {
        match dns {
            matc::mdns2::MdnsEvent::ServiceDiscovered {name, records: _, target } => {
                if name != "_matter._tcp.local." && name != "_matterc._udp.local." {
                    continue;
                }
                let matter_info = match matc::discover::extract_matter_info(&target, &mdns) .await {
                    Ok(info) => info,
                    Err(e) => {
                        log::warn!("Error extracting Matter info for service {}: {:?}", name, e);
                        continue;
                    }
                };
                match cache.insert(matter_info.instance.clone(), true) {
                    Some(_) => {
                        log::debug!("Already seen instance {}, skipping", matter_info.instance);
                        continue;
                    }
                    None => {
                        // continue
                    }
                }
                if cli.compact {
                    matter_info.print_compact();
                } else {
                    let e = print_service(&target, &mdns).await;
                    if let Err(e) = e {
                        log::warn!("Error processing service {}: {:?}", name, e);
                    }
                }
            },
            matc::mdns2::MdnsEvent::ServiceExpired { name, rtype } => {
                log::debug!("Service expired: {} (type {})", name, rtype);
            },
        }
    }

}
