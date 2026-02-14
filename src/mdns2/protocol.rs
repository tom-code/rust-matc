//! basic mDNS protocol: record caching, wire-format encoding, multicast sockets, send loop.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use byteorder::{BigEndian, WriteBytesExt};
use socket2::{Domain, Protocol, Type};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio_util::sync::CancellationToken;

use crate::mdns;

pub(super) const MDNS_ADDR_V4: &str = "224.0.0.251:5353";
pub(super) const MDNS_ADDR_V6: &str = "[ff02::fb]:5353";

#[derive(Debug, Clone)]
pub struct CachedRecord {
    pub rr: mdns::RR,
    pub received_at: Instant,
    pub ttl: Duration,
}

impl CachedRecord {
    fn is_expired(&self) -> bool {
        self.received_at.elapsed() > self.ttl
    }
}

/// Cache of DNS resource records, keyed by "lowercase name, record type".
pub struct RecordCache {
    pub(super) entries: HashMap<(String, u16), Vec<CachedRecord>>,
}

impl RecordCache {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Insert or update records from a DNS response.
    /// TTL=0 removes the specific record whose rdata matches (RFC 6762 10.1).
    pub fn ingest(&mut self, rr: &mdns::RR) -> bool {
        let key = (rr.name.to_lowercase(), rr.typ);
        if rr.ttl == 0 {
            if let Some(vec) = self.entries.get_mut(&key) {
                vec.retain(|c| c.rr.rdata != rr.rdata);
                if vec.is_empty() {
                    self.entries.remove(&key);
                }
            }
            return false;
        }
        let cached = CachedRecord {
            rr: rr.clone(),
            received_at: Instant::now(),
            ttl: Duration::from_secs(rr.ttl as u64),
        };
        let vec = self.entries.entry(key).or_default();
        // Replace if same rdata, otherwise add
        if let Some(existing) = vec.iter_mut().find(|c| c.rr.rdata == rr.rdata) {
            *existing = cached;
            false
        } else {
            vec.push(cached);
            true
        }
    }

    /// Remove expired entries. Returns list of (name, type) keys that were fully removed.
    pub fn evict_expired(&mut self) -> Vec<(String, u16)> {
        let mut expired_keys = Vec::new();
        self.entries.retain(|key, records| {
            records.retain(|c| !c.is_expired());
            if records.is_empty() {
                expired_keys.push(key.clone());
                false
            } else {
                true
            }
        });
        expired_keys
    }

    /// Lookup non-expired records by exact (lowercase name, type).
    pub fn lookup(&self, name: &str, qtype: u16) -> Vec<mdns::RR> {
        let key = (name.to_lowercase(), qtype);
        self.entries
            .get(&key)
            .map(|v| {
                v.iter()
                    .filter(|c| !c.is_expired())
                    .map(|c| c.rr.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Lookup all non-expired records matching a name (any type).
    pub fn lookup_name(&self, name: &str) -> Vec<mdns::RR> {
        let lower = name.to_lowercase();
        self.entries
            .iter()
            .filter(|((n, _), _)| *n == lower)
            .flat_map(|(_, v)| v.iter().filter(|c| !c.is_expired()).map(|c| c.rr.clone()))
            .collect()
    }
}

impl Default for RecordCache {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)]
pub(super) enum SendCommand {
    /// Send to multicast on all sockets
    Multicast(Vec<u8>),
    /// Send to a specific address (for unicast response)
    Unicast(Vec<u8>, std::net::SocketAddr),
}

/// Encode a single resource record to wire format.
pub(super) fn encode_rr(rr: &mdns::RR, out: &mut Vec<u8>) -> Result<()> {
    mdns::encode_label(&rr.name, out)?;
    out.write_u16::<BigEndian>(rr.typ)?;
    out.write_u16::<BigEndian>(rr.class)?;
    out.write_u32::<BigEndian>(rr.ttl)?;

    if rr.typ == mdns::TYPE_SRV {
        // SRV: priority(2) + weight(2) + port(2) + target(variable)
        let mut rdata = Vec::new();
        // First 6 bytes are priority, weight, port from existing rdata if available
        if rr.rdata.len() >= 6 {
            rdata.extend_from_slice(&rr.rdata[..6]);
        } else {
            rdata.write_u16::<BigEndian>(0)?; // priority
            rdata.write_u16::<BigEndian>(0)?; // weight
            rdata.write_u16::<BigEndian>(0)?; // port
        }
        // If there's a target field, re-encode it as a label
        if let Some(ref target) = rr.target {
            // Rebuild rdata with the target label
            let mut srv_rdata = Vec::new();
            srv_rdata.extend_from_slice(&rdata[..6]);
            mdns::encode_label(target.trim_end_matches('.'), &mut srv_rdata)?;
            out.write_u16::<BigEndian>(srv_rdata.len() as u16)?;
            out.extend_from_slice(&srv_rdata);
        } else {
            out.write_u16::<BigEndian>(rr.rdata.len() as u16)?;
            out.extend_from_slice(&rr.rdata);
        }
    } else {
        out.write_u16::<BigEndian>(rr.rdata.len() as u16)?;
        out.extend_from_slice(&rr.rdata);
    }
    Ok(())
}

/// Build an mDNS response packet from answer and additional record lists.
pub(super) fn build_response(answers: &[mdns::RR], additional: &[mdns::RR]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(512);
    out.write_u16::<BigEndian>(0)?; // transaction id
    out.write_u16::<BigEndian>(0x8400)?; // flags: response, authoritative
    out.write_u16::<BigEndian>(0)?; // questions
    out.write_u16::<BigEndian>(answers.len() as u16)?;
    out.write_u16::<BigEndian>(0)?; // authority
    out.write_u16::<BigEndian>(additional.len() as u16)?;

    for rr in answers {
        encode_rr(rr, &mut out)?;
    }
    for rr in additional {
        encode_rr(rr, &mut out)?;
    }
    Ok(out)
}

pub(super) fn create_multicast_socket_v4() -> Result<std::net::UdpSocket> {
    let sock = socket2::Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    #[cfg(not(target_os = "windows"))]
    sock.set_reuse_port(true)?;
    let addr: SocketAddrV4 = "0.0.0.0:5353".parse()?;
    sock.bind(&socket2::SockAddr::from(addr))?;
    let maddr: Ipv4Addr = "224.0.0.251".parse()?;
    sock.join_multicast_v4(&maddr, &Ipv4Addr::UNSPECIFIED)?;
    sock.set_nonblocking(true)?;
    Ok(sock.into())
}

pub(super) fn create_multicast_socket_v6(interface: u32) -> Result<std::net::UdpSocket> {
    let sock = socket2::Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    #[cfg(not(target_os = "windows"))]
    sock.set_reuse_port(true)?;
    let addr: SocketAddrV6 = "[::]:5353".parse()?;
    sock.bind(&socket2::SockAddr::from(addr))?;
    let maddr: Ipv6Addr = "ff02::fb".parse()?;
    sock.join_multicast_v6(&maddr, interface)?;
    sock.set_multicast_if_v6(interface)?;
    sock.set_nonblocking(true)?;
    Ok(sock.into())
}

pub(super) fn get_local_ips() -> (Vec<Ipv4Addr>, Vec<Ipv6Addr>) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    if let Ok(ifaces) = if_addrs::get_if_addrs() {
        for iface in ifaces {
            match iface.ip() {
                std::net::IpAddr::V4(ip) if !ip.is_loopback() => v4.push(ip),
                std::net::IpAddr::V6(ip) if !ip.is_loopback() => v6.push(ip),
                _ => {}
            }
        }
    }
    (v4, v6)
}

pub(super) struct McastSocket {
    pub sock: Arc<UdpSocket>,
    pub multicast_addr: &'static str,
}

pub(super) async fn send_loop(
    sockets: Vec<McastSocket>,
    mut rx: UnboundedReceiver<SendCommand>,
    cancel: CancellationToken,
) {
    loop {
        let cmd = tokio::select! {
            cmd = rx.recv() => {
                match cmd {
                    Some(c) => c,
                    None => return,
                }
            }
            _ = cancel.cancelled() => return,
        };

        match cmd {
            SendCommand::Multicast(data) => {
                for ms in &sockets {
                    let _ = ms.sock.send_to(&data, ms.multicast_addr).await;
                }
            }
            SendCommand::Unicast(data, addr) => {
                // Send on first socket that succeeds
                for ms in &sockets {
                    if ms.sock.send_to(&data, addr).await.is_ok() {
                        break;
                    }
                }
            }
        }
    }
}

