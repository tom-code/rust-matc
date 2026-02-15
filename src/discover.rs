//! Module with very simple mdns based discovery of matter devices.
//! Usually application shall discover devices using these methods and filter according discriminator.
//! This module tries to send mdns using ipv4 and ipv6 multicast at same time.
//! If more control over discovery mechanism is required, it may be better to use some external mdns library.

use crate::{mdns::{self, DnsMessage}, mdns2};
use anyhow::{Context, Result};
use byteorder::ReadBytesExt;
use std::{
    collections::{BTreeMap, HashMap},
    io::{Cursor, Read},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};
use tokio_util::bytes::Buf;

#[derive(Debug, Clone)]
pub enum CommissioningMode {
    No,
    Yes,
    WithPasscode,
}

#[derive(Debug, Clone)]
pub struct MatterDeviceInfo {
    pub instance: String,
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

impl MatterDeviceInfo {
    pub fn print_compact(&self) {
        let mut info = format!("{} ({})", self.instance, self.device);
        if let Some(name) = &self.name {
            info += &format!(", name: {}", name);
        }
        if let Some(vendor_id) = &self.vendor_id {
            info += &format!(", vendor_id: {}", vendor_id);
        }
        if let Some(product_id) = &self.product_id {
            info += &format!(", product_id: {}", product_id);
        }
        if let Some(discriminator) = &self.discriminator {
            info += &format!(", discriminator: {}", discriminator);
        }
        if let Some(cm) = &self.commissioning_mode {
            info += &format!(", commissioning_mode: {:?}", cm);
        }
        if let Some(pairing_hint) = &self.pairing_hint {
            info += &format!(", pairing_hint: {}", pairing_hint);
        }
        if let Some(port) = &self.port {
            info += &format!(", port: {}", port);
        }
        println!("{}", info);
        if !self.ips.is_empty() {
            println!("  ips:");
            for ip in &self.ips {
                println!("      {}", ip);
            }
        }

    }
}


pub fn parse_txt_records(data: &[u8]) -> Result<HashMap<String, String>> {
    let mut cursor = Cursor::new(data);
    let mut out = HashMap::new();
    while cursor.remaining() > 0 {
        let len = cursor.read_u8()?;
        let mut buf = vec![0; len as usize];
        cursor.read_exact(buf.as_mut_slice())?;
        let splitstr = std::str::from_utf8(&buf)?.splitn(2, "=");
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

pub fn to_matter_info2(msg: &DnsMessage, svc: &str) -> Result<Vec<MatterDeviceInfo>> {
    let mut out = Vec::new();
    let mut matter_service = false;
    let svcname = ".".to_owned() + svc + ".";
    for answer in &msg.answers {
        if answer.name == svcname[1..] {
            matter_service = true
        }
    }
    if !matter_service {
        return Err(anyhow::anyhow!("not matter service"));
    }
    let mut services = HashMap::new();
    let mut targets = HashMap::new();
    for additional in &msg.additional {
        if additional.typ == mdns::TYPE_A {
            let arr: [u8; 4] = match additional.rdata.clone().try_into() {
                Ok(v) => v,
                Err(_e) => return Err(anyhow::anyhow!("A record is not correct")),
            };
            let val = IpAddr::V4(Ipv4Addr::from_bits(u32::from_be_bytes(arr)));
            if !targets.contains_key(&additional.name) {
                targets.insert(additional.name.clone(), Vec::new());
            }
            targets.get_mut(&additional.name).unwrap().push(val);
        }
        if additional.typ == mdns::TYPE_AAAA {
            let arr: [u8; 16] = match additional.rdata.clone().try_into() {
                Ok(v) => v,
                Err(_e) => return Err(anyhow::anyhow!("AAAA record is not correct")),
            };
            let val = IpAddr::V6(Ipv6Addr::from_bits(u128::from_be_bytes(arr)));
            if !targets.contains_key(&additional.name) {
                targets.insert(additional.name.clone(), Vec::new());
            }
            targets.get_mut(&additional.name).unwrap().push(val);
        }
    }
    let mut all = msg.additional.to_vec();
    all.append(&mut msg.answers.to_vec());
    for additional in &all {
        if additional.typ == mdns::TYPE_SRV {
            let service_name = remove_string_suffix(&additional.name, &svcname);
            if additional.rdata.len() < 6 {
                continue;
            }
            let port = ((additional.rdata[4] as u16) << 8) | (additional.rdata[5] as u16);
            let target_name = {
                if let Some(at) = additional.target.as_ref() {
                    at
                } else {
                    continue;
                }
            };
            let target_ip = targets.get(target_name).cloned().unwrap_or_default();
            let mi = MatterDeviceInfo {
                instance: service_name.clone(),
                device: remove_string_suffix(target_name, ".local.").to_owned(),
                ips: target_ip,
                name: None,
                discriminator: None,
                commissioning_mode: None,
                pairing_hint: None,
                source_ip: msg.source.to_string(),
                vendor_id: None,
                product_id: None,
                port: Some(port),
            };
            services.insert(service_name, mi);
        }
    }
    for s in services.values() {
        out.push(s.clone());
    }

    Ok(out)
}

pub fn to_matter_info(msg: &DnsMessage, svc: &str) -> Result<MatterDeviceInfo> {
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
        instance: service.context("service name not detected")?,
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


async fn discover_common2(timeout: Duration, svc_type: &str) -> Result<Vec<MatterDeviceInfo>> {
    let stop = tokio_util::sync::CancellationToken::new();
    let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel::<DnsMessage>();

    mdns::discover(svc_type, mdns::QTYPE_ANY, sender, stop.child_token()).await?;

    tokio::spawn(async move {
        tokio::time::sleep(timeout).await;
        stop.cancel();
    });
    let mut cache = HashMap::new();
    let mut out: Vec<MatterDeviceInfo> = Vec::new();
    while let Some(dns) = receiver.recv().await {
        if cache.contains_key(&dns) {
            continue;
        }
        let info = match to_matter_info2(&dns, svc_type) {
            Ok(info) => info,
            Err(e) => {
                log::trace!("failed to parse mdns message from {}: {:?}", dns.source, e);
                continue;
            },
        };
        for i in &info {
            out.push(i.clone());
        }
        cache.insert(dns, true);
    }
    Ok(out)
}

/// Discover commissionable devices using mdns
pub async fn discover_commissionable2(timeout: Duration) -> Result<Vec<MatterDeviceInfo>> {
    discover_common2(timeout, "_matterc._udp.local").await
}

/// Discover commissioned devices using mdns
pub async fn discover_commissioned2(timeout: Duration, device: &Option<String>) -> Result<Vec<MatterDeviceInfo>> {
    let query = {
        match device {
            None => "_matter._tcp.local".to_owned(),
            Some(d) => format!("{}._matter._tcp.local", d),
        }
    };
    discover_common2(timeout, &query).await
}



pub async fn extract_matter_info(target: &str, mdns: &mdns2::MdnsService) -> Result<MatterDeviceInfo> {
    let txt_records = mdns.lookup(target, mdns::TYPE_TXT).await;
    let mut txt_info = HashMap::new();
    for txt_rr in txt_records {
        txt_info.extend(parse_txt_records(&txt_rr.rdata)?);
    }
    let srv_records = mdns.lookup(target, mdns::TYPE_SRV).await;
    let srv_rr = srv_records.first().ok_or_else(|| anyhow::anyhow!("No SRV record found for {}", target))?;
    let (srv_target, port) = match srv_rr.data {
        mdns::RRData::SRV { ref target, port, .. } => (target.clone(), port),
        _ => return Err(anyhow::anyhow!("Invalid SRV record for {}", target)),
    };
    let mut ips = Vec::new();
    let a_records = mdns.lookup(&srv_target, mdns::TYPE_A).await;
    for a_rr in a_records {
        if let mdns::RRData::A(ip) = a_rr.data {
            ips.push(ip.into());
        }
    }
    let aaaa_records = mdns.lookup(&srv_target, mdns::TYPE_AAAA).await;
    for aaaa_rr in aaaa_records {
        if let mdns::RRData::AAAA(ip) = aaaa_rr.data {
            ips.push(ip.into());
        }
    }
    let (vendor_id, product_id) = {
        let vp = txt_info.get("VP");
        if let Some(vp) = vp {
            let mut parts = vp.split('+');
            let vendor_id = parts.next();
            let product_id = parts.next();
            (vendor_id.map(|v| v.to_owned()), product_id.map(|p| p.to_owned()))
        } else {
            (None, None)
        }
    };
    let discriminator = txt_info.get("D").cloned();
    let name = txt_info.get("DN").cloned();
    let commissioning_mode = match txt_info.get("CM") {
                Some(v) => match v.as_str() {
                    "0" => Some(CommissioningMode::No),
                    "1" => Some(CommissioningMode::Yes),
                    "2" => Some(CommissioningMode::WithPasscode),
                    _ => None,
                },
                None => None,
            };
    let pairing_hint = txt_info.get("PH").cloned();
    Ok(MatterDeviceInfo {
        name,
        instance: target.trim_end_matches('.').to_owned(),
        device: srv_target.trim_end_matches('.').to_owned(),
        ips,
        vendor_id,
        product_id,
        discriminator,
        commissioning_mode,
        pairing_hint,
        source_ip: "".to_owned(),
        port: Some(port),
    })
}