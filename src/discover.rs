use std::{collections::HashMap, net::{IpAddr, Ipv4Addr, Ipv6Addr}, time::Duration};
use anyhow::{Context, Result};
use crate::mdns::{self, DnsMessage};



#[derive(Debug)]
pub struct MatterDeviceInfo {
    pub service: String,
    pub device: String,
    pub ips: Vec<IpAddr>
}



fn to_matter(msg: &DnsMessage) -> Result<MatterDeviceInfo> {
    let mut device = None;
    let mut service = None;
    let mut ips = Vec::new();

    let mut matter_service = false;
    for answer in &msg.answers {
        if answer.name == "_matterc._udp.local." {
            matter_service = true
        }
    }
    for additional in &msg.additional {
        if additional.typ == mdns::TYPE_A {
            let arr : [u8; 4] = match additional.rdata.clone().try_into() {
                Ok(v) => v,
                Err(_e) => return Err(anyhow::anyhow!("A record is not correct")),
            };
            let val = IpAddr::V4(Ipv4Addr::from_bits(u32::from_be_bytes(arr)));
            ips.push(val);
            device = Some(additional.name.clone().strip_suffix(".local.").get_or_insert(&additional.name).to_owned());
        }
        if additional.typ == mdns::TYPE_AAAA {
            let arr : [u8; 16] = match additional.rdata.clone().try_into() {
                Ok(v) => v,
                Err(_e) => return Err(anyhow::anyhow!("AAAA record is not correct")),
            };
            let val = IpAddr::V6(Ipv6Addr::from_bits(u128::from_be_bytes(arr)));
            ips.push(val);
            device = Some(additional.name.clone().strip_suffix(".local.").get_or_insert(&additional.name).to_owned());
        }
        if additional.typ == mdns::TYPE_SRV {
            service = Some(additional.name.clone().strip_suffix("._matterc._udp.local.").get_or_insert(&additional.name).to_owned());
        }
    }

    if !matter_service {
        return Err(anyhow::anyhow!("not matter service"));
    }

    Ok(MatterDeviceInfo {
        service: service.context("service name not detected")?,
        device: device.context("device name not detected")?,
        ips,
    })
}

pub async fn discover_commissionable(timeout: Duration) -> Result<Vec<MatterDeviceInfo>> {
    let stop = tokio_util::sync::CancellationToken::new();
    let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel::<DnsMessage>();

    mdns::discover("_matterc._udp.local", sender, stop.child_token()).await?;


    tokio::spawn(async move {
        tokio::time::sleep(timeout).await;
        stop.cancel();
    });
    let mut cache = HashMap::new();
    let mut out = Vec::new();
    while let Some(dns) = receiver.recv().await {
        if cache.contains_key(&dns) {
            continue
        }
        //dns.dump();
        let info = match to_matter(&dns) {
            Ok(info) => info,
            Err(_) => continue,
        };
        //println!("{:?}", info);
        out.push(info);
        cache.insert(dns, true);
    }
    Ok(out)
}