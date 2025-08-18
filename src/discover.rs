//! Module with very simple mdns based discovery of matter devices.
//! Usually application shall discover devices using these methods and filter according discriminator.
//! This module tries to send mdns using ipv4 and ipv6 multicast at same time.
//! If more control over discovery mechanism is required, it may be better to use some external mdns library.

use crate::mdns::{self, DnsMessage};
use anyhow::{Context, Result};
use byteorder::ReadBytesExt;
use std::{
    collections::{BTreeMap, HashMap},
    io::{Cursor, Read},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};
use tokio_util::bytes::Buf;

#[derive(Debug)]
pub enum CommissioningMode {
    No,
    Yes,
    WithPasscode,
}

#[derive(Debug)]
pub struct MatterDeviceInfo {
    pub service: String,
    pub device: String,
    pub ips: Vec<IpAddr>,
    pub name: Option<String>,
    pub vendor_id: Option<String>,
    pub product_id: Option<String>,
    pub discriminator: Option<String>,
    pub commissioning_mode: Option<CommissioningMode>,
    pub pairing_hint: Option<String>,
    pub source_ip: String,
    pub port: Option<u16>,
}

fn parse_txt_records(data: &[u8]) -> Result<HashMap<String, String>> {
    let mut cursor = Cursor::new(data);
    let mut out = HashMap::new();
    while cursor.remaining() > 0 {
        let len = cursor.read_u8()?;
        let mut buf = vec![0; len as usize];
        cursor.read_exact(buf.as_mut_slice())?;
        let splitstr = std::str::from_utf8(&buf)?.split("=");
        let x: Vec<&str> = splitstr.collect();
        if x.len() == 2 {
            out.insert(x[0].to_owned(), x[1].to_owned());
        }
    }
    Ok(out)
}

fn remove_string_suffix(string: &str, suffix: &str) -> String {
    if let Some(s) = string.strip_suffix(suffix) {
        s.to_owned()
    } else {
        string.to_owned()
    }
}

fn to_matter_info(msg: &DnsMessage, svc: &str) -> Result<MatterDeviceInfo> {
    let mut device = None;
    let mut service = None;
    let mut ips = BTreeMap::new();
    let mut name = None;
    let mut discriminator = None;
    let mut cm = None;
    let mut pairing_hint = None;
    let mut vendor_id = None;
    let mut product_id = None;
    let mut port: Option<u16> = None;

    let mut matter_service = false;
    let svcname = ".".to_owned() + svc + ".";
    for answer in &msg.answers {
        if answer.name == svcname[1..] {
            matter_service = true
        }
    }
    for additional in &msg.additional {
        if additional.typ == mdns::TYPE_A {
            let arr: [u8; 4] = match additional.rdata.clone().try_into() {
                Ok(v) => v,
                Err(_e) => return Err(anyhow::anyhow!("A record is not correct")),
            };
            let val = IpAddr::V4(Ipv4Addr::from_bits(u32::from_be_bytes(arr)));
            ips.insert(val, true);
            device = Some(remove_string_suffix(&additional.name, ".local."));
        }
        if additional.typ == mdns::TYPE_AAAA {
            let arr: [u8; 16] = match additional.rdata.clone().try_into() {
                Ok(v) => v,
                Err(_e) => return Err(anyhow::anyhow!("AAAA record is not correct")),
            };
            let val = IpAddr::V6(Ipv6Addr::from_bits(u128::from_be_bytes(arr)));
            ips.insert(val, true);
            device = Some(remove_string_suffix(&additional.name, ".local."));
        }
        if additional.typ == mdns::TYPE_SRV {
            service = Some(remove_string_suffix(&additional.name, &svcname));
            if additional.rdata.len() >= 6 {
                port = Some(((additional.rdata[4] as u16) << 8) | (additional.rdata[5] as u16))
            }
        }
        if additional.typ == mdns::TYPE_TXT {
            let rec = parse_txt_records(&additional.rdata)?;
            name = rec.get("DN").cloned();
            discriminator = rec.get("D").cloned();
            pairing_hint = rec.get("PH").cloned();
            if let Some(vp) = rec.get("VP") {
                let mut split = vp.split("+");
                vendor_id = split.next().map(str::to_owned);
                product_id = split.next().map(str::to_owned);
            }
            cm = match rec.get("CM") {
                Some(v) => match v.as_str() {
                    "0" => Some(CommissioningMode::No),
                    "1" => Some(CommissioningMode::Yes),
                    "2" => Some(CommissioningMode::WithPasscode),
                    _ => None,
                },
                None => None,
            };
        }
    }

    if !matter_service {
        return Err(anyhow::anyhow!("not matter service"));
    }

    Ok(MatterDeviceInfo {
        service: service.context("service name not detected")?,
        device: device.context("device name not detected")?,
        ips: ips.into_keys().collect(),
        name,
        discriminator,
        commissioning_mode: cm,
        pairing_hint,
        source_ip: msg.source.to_string(),
        vendor_id,
        product_id,
        port,
    })
}

async fn discover_common(timeout: Duration, svc_type: &str) -> Result<Vec<MatterDeviceInfo>> {
    let stop = tokio_util::sync::CancellationToken::new();
    let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel::<DnsMessage>();

    mdns::discover(svc_type, mdns::QTYPE_ANY, sender, stop.child_token()).await?;

    tokio::spawn(async move {
        tokio::time::sleep(timeout).await;
        stop.cancel();
    });
    let mut cache = HashMap::new();
    let mut out = Vec::new();
    while let Some(dns) = receiver.recv().await {
        if cache.contains_key(&dns) {
            continue;
        }
        let info = match to_matter_info(&dns, svc_type) {
            Ok(info) => info,
            Err(_) => continue,
        };
        out.push(info);
        cache.insert(dns, true);
    }
    Ok(out)
}

/// Discover commissionable devices using mdns
pub async fn discover_commissionable(timeout: Duration) -> Result<Vec<MatterDeviceInfo>> {
    discover_common(timeout, "_matterc._udp.local").await
}

/// Discover commissioned devices using mdns
pub async fn discover_commissioned(timeout: Duration) -> Result<Vec<MatterDeviceInfo>> {
    discover_common(timeout, "_matter._tcp.local").await
}
