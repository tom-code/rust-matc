//! Very simple mdns client library

use std::io::{Cursor, Read, Write};

use anyhow::Result;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use socket2::{Domain, Protocol, Type};

pub const TYPE_A: u16 = 1;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_SRV: u16 = 33;
pub const QTYPE_ANY: u16 = 0xff;

fn encode_label(label: &str, out: &mut Vec<u8>) -> Result<()> {
    for seg in label.split(".") {
        let bytes = seg.as_bytes();
        out.write_u8(bytes.len() as u8)?;
        out.write_all(bytes)?;
    }
    out.write_u8(0)?;
    Ok(())
}

fn create_query(label: &str, qtype: u16) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(512);
    out.write_u16::<BigEndian>(0)?; // transaction id
    out.write_u16::<BigEndian>(0)?; // flags
    out.write_u16::<BigEndian>(1)?; // questions
    out.write_u16::<BigEndian>(0)?; // answers
    out.write_u16::<BigEndian>(0)?; // authority
    out.write_u16::<BigEndian>(0)?; // additional

    encode_label(label, &mut out)?;

    out.write_u16::<BigEndian>(qtype)?;
    out.write_u16::<BigEndian>(0x0001)?; // class
    Ok(out)
}

fn read_label(data: &[u8], cursor: &mut Cursor<&[u8]>) -> Result<String> {
    let mut out = Vec::new();
    loop {
        let n = cursor.read_u8()?;
        if n == 0 {
            break;
        } else if n & 0xc0 == 0xc0 {
            let off = {
                let off = n & 0x3f;
                ((off as usize) << 8) | (cursor.read_u8()? as u16) as usize
            };
            let frag = read_label(data, &mut Cursor::new(&data[off..]))?;
            out.extend_from_slice(frag.as_bytes());
            break;
        } else {
            let mut b = vec![0; n as usize];
            cursor.read_exact(&mut b)?;
            out.extend_from_slice(&b);
            out.extend_from_slice(b".");
        }
    }
    Ok(std::str::from_utf8(&out)?.to_owned())
}

#[derive(Debug, Eq, PartialEq, Hash)]
pub struct RR {
    pub name: String,
    pub typ: u16,
    pub class: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

#[derive(Debug, Eq, PartialEq, Hash)]
pub struct Query {
    pub name: String,
    pub typ: u16,
    pub class: u16,
}

#[derive(Debug, Eq, PartialEq, Hash)]
pub struct DnsMessage {
    pub source: std::net::SocketAddr,
    pub transaction: u16,
    pub flags: u16,
    pub queries: Vec<Query>,
    pub answers: Vec<RR>,
    pub authority: Vec<RR>,
    pub additional: Vec<RR>,
}

impl RR {
    pub fn dump(&self, indent: usize) {
        println!(
            "{} {} {}",
            " ".to_owned().repeat(indent),
            self.name,
            self.typ
        )
    }
}

impl Query {
    pub fn dump(&self, indent: usize) {
        println!(
            "{} {} {}",
            " ".to_owned().repeat(indent),
            self.name,
            self.typ
        )
    }
}

impl DnsMessage {
    pub fn dump(&self) {
        println!("{:?} {} {:x}", self.source, self.transaction, self.flags);
        println!("  queries:");
        for queries in &self.queries {
            queries.dump(4);
        }
        println!("  answers:");
        for answer in &self.answers {
            answer.dump(4);
        }
        println!("  authority:");
        for authority in &self.authority {
            authority.dump(4);
        }
        println!("  additional:");
        for additional in &self.additional {
            additional.dump(4);
        }
    }
}

fn parse_rr(data: &[u8], cursor: &mut Cursor<&[u8]>) -> Result<RR> {
    let name = read_label(data, cursor)?;
    let typ = cursor.read_u16::<BigEndian>()?;
    let class = cursor.read_u16::<BigEndian>()?;
    let ttl = cursor.read_u32::<BigEndian>()?;
    let dlen = cursor.read_u16::<BigEndian>()?;
    let mut rdata = vec![0; dlen as usize];
    cursor.read_exact(&mut rdata)?;

    Ok(RR {
        name,
        typ,
        class,
        ttl,
        rdata,
    })
}

fn parse_q(data: &[u8], cursor: &mut Cursor<&[u8]>) -> Result<Query> {
    let name = read_label(data, cursor)?;
    let typ = cursor.read_u16::<BigEndian>()?;
    let class = cursor.read_u16::<BigEndian>()?;

    Ok(Query { name, typ, class })
}

fn parse_dns(data: &[u8], source: std::net::SocketAddr) -> Result<DnsMessage> {
    let mut cursor = Cursor::new(data);
    let transaction = cursor.read_u16::<BigEndian>()?;
    let flags = cursor.read_u16::<BigEndian>()?;
    let nquestions = cursor.read_u16::<BigEndian>()?;
    let nanswers = cursor.read_u16::<BigEndian>()?;
    let nauthority = cursor.read_u16::<BigEndian>()?;
    let nadditional = cursor.read_u16::<BigEndian>()?;

    let mut queries = Vec::new();
    let mut answers = Vec::new();
    let mut additional = Vec::new();
    let mut authority = Vec::new();

    for _ in 0..nquestions {
        queries.push(parse_q(data, &mut cursor)?);
    }
    for _ in 0..nanswers {
        answers.push(parse_rr(data, &mut cursor)?);
    }
    for _ in 0..nauthority {
        authority.push(parse_rr(data, &mut cursor)?);
    }
    for _ in 0..nadditional {
        additional.push(parse_rr(data, &mut cursor)?);
    }

    Ok(DnsMessage {
        source,
        transaction,
        flags,
        queries,
        answers,
        authority,
        additional,
    })
}

async fn discoverv4(
    label: &str,
    qtype: u16,
    sender: tokio::sync::mpsc::UnboundedSender<DnsMessage>,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    let stdsocket = socket2::Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    stdsocket.set_reuse_address(true)?;
    #[cfg(not(target_os = "windows"))]
    stdsocket.set_reuse_port(true)?;
    let addr: std::net::SocketAddrV4 = "0.0.0.0:5353".parse()?;
    stdsocket.bind(&socket2::SockAddr::from(addr))?;
    let maddr: std::net::Ipv4Addr = "224.0.0.251".parse()?;
    stdsocket.join_multicast_v4(&maddr, &std::net::Ipv4Addr::UNSPECIFIED)?;
    stdsocket.set_nonblocking(true)?;
    let socket = tokio::net::UdpSocket::from_std(stdsocket.into())?;
    let query = create_query(label, qtype)?;
    socket.send_to(&query, "224.0.0.251:5353").await?;
    loop {
        let mut buf = vec![0; 1024];
        //let (n, addr) = socket.recv_from(&mut buf).await?;
        let (n, addr) = tokio::select! {
            v = socket.recv_from(&mut buf) => v?,
            _ = cancel.cancelled() => return Ok(())
        };

        buf.resize(n, 0);
        let dns = parse_dns(&buf, addr)?;
        if dns.flags == 0 {
            // ignore requests
            continue;
        }
        sender.send(dns)?;
    }
}

async fn discoverv6(
    label: &str,
    qtype: u16,
    interface: u32,
    sender: tokio::sync::mpsc::UnboundedSender<DnsMessage>,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    let stdsocket = socket2::Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    stdsocket.set_reuse_address(true)?;
    #[cfg(not(target_os = "windows"))]
    stdsocket.set_reuse_port(true)?;
    let addr: std::net::SocketAddrV6 = "[::]:5353".parse()?;
    stdsocket.bind(&socket2::SockAddr::from(addr))?;
    let maddr: std::net::Ipv6Addr = "ff02::fb".parse()?;
    stdsocket.join_multicast_v6(&maddr, interface)?;
    stdsocket.set_multicast_if_v6(interface)?;
    stdsocket.set_nonblocking(true)?;
    let socket = tokio::net::UdpSocket::from_std(stdsocket.into())?;
    let query = create_query(label, qtype)?;
    socket.send_to(&query, "[ff02::fb]:5353").await?;
    loop {
        let mut buf = vec![0; 1024];
        //let (n, addr) = socket.recv_from(&mut buf).await?;
        let (n, addr) = tokio::select! {
            v = socket.recv_from(&mut buf) => v?,
            _ = cancel.cancelled() => return Ok(())
        };
        buf.resize(n, 0);
        let dns = parse_dns(&buf, addr)?;
        if dns.flags == 0 {
            // ignore requests
            continue;
        }
        sender.send(dns)?;
    }
}

pub async fn discover(
    label: &str,
    qtype: u16,
    sender: tokio::sync::mpsc::UnboundedSender<DnsMessage>,
    stop: tokio_util::sync::CancellationToken,
) -> Result<()> {
    let ifaces = if_addrs::get_if_addrs();
    if let Ok(ifaces) = ifaces {
        for iface in ifaces {
            let stop_child = stop.child_token();
            if !iface.ip().is_ipv6() {
                continue;
            }
            if let Some(index) = iface.index {
                let sender2 = sender.clone();
                let label = label.to_owned();
                tokio::spawn(async move {
                    _ = discoverv6(&label, qtype, index, sender2, stop_child).await;
                });
            }
        }
    };

    let stop_child = stop.child_token();
    let label = label.to_owned();
    tokio::spawn(async move {
        _ = discoverv4(&label, qtype, sender, stop_child).await;
    });

    Ok(())
}
