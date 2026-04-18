//! mDNS Response Packet Sender
//!
//! Usage:
//!   cargo run --example mdns_send -- <hex_packet>
//!

use anyhow::Result;
use byteorder::{BigEndian, WriteBytesExt};
use clap::Parser;
use socket2::{Domain, Protocol, Socket, Type};
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};

/// DNS record types for mDNS responses
#[derive(Debug, Clone)]
pub enum DnsRecord {
    Ptr { name: String, target: String, ttl: u32 },
    Srv { name: String, priority: u16, weight: u16, port: u16, target: String, ttl: u32 },
    Txt { name: String, entries: Vec<String>, ttl: u32 },
    A { name: String, addr: Ipv4Addr, ttl: u32 },
    Aaaa { name: String, addr: Ipv6Addr, ttl: u32 },
}

/// Builder for constructing mDNS response packets
#[derive(Debug, Clone, Default)]
pub struct MdnsResponseBuilder {
    answers: Vec<DnsRecord>,
    additional: Vec<DnsRecord>,
}

impl MdnsResponseBuilder {
    /// Create a new empty response builder
    pub fn new() -> Self {
        Self {
            answers: Vec::new(),
            additional: Vec::new(),
        }
    }

    /// Add a record to the answer section
    pub fn add_answer(mut self, record: DnsRecord) -> Self {
        self.answers.push(record);
        self
    }

    /// Add a record to the additional section
    pub fn add_additional(mut self, record: DnsRecord) -> Self {
        self.additional.push(record);
        self
    }

    /// Encode the response into wire format
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(512);

        // DNS header (12 bytes)
        out.write_u16::<BigEndian>(0)?; // transaction ID = 0
        out.write_u16::<BigEndian>(0x8400)?; // flags: response + authoritative
        out.write_u16::<BigEndian>(0)?; // question count = 0
        out.write_u16::<BigEndian>(self.answers.len() as u16)?; // answer count
        out.write_u16::<BigEndian>(0)?; // authority count = 0
        out.write_u16::<BigEndian>(self.additional.len() as u16)?; // additional count

        let name_offsets = &mut std::collections::HashMap::new();
        // Encode answer records
        for record in &self.answers {
            encode_record(record, &mut out, name_offsets)?;
        }

        // Encode additional records
        for record in &self.additional {
            encode_record(record, &mut out, name_offsets)?;
        }

        Ok(out)
    }
}

/// Encode a single DNS record to wire format
fn encode_record(record: &DnsRecord, out: &mut Vec<u8>, name_offsets: &mut std::collections::HashMap<String, usize>) -> Result<()> {
    match record {
        DnsRecord::Ptr { name, target, ttl } => {
            // Encode name
            matc::mdns::encode_label_compressed(name, out, name_offsets)?;
            // Type PTR = 12
            out.write_u16::<BigEndian>(matc::mdns::TYPE_PTR)?;
            // Class IN = 1
            out.write_u16::<BigEndian>(0x0001)?;
            // TTL
            out.write_u32::<BigEndian>(*ttl)?;
            // RDATA: encode target as label
            let mut rdata = Vec::new();
            matc::mdns::encode_label(target, &mut rdata)?;
            out.write_u16::<BigEndian>(rdata.len() as u16)?;
            out.write_all(&rdata)?;
        }
        DnsRecord::Srv { name, priority, weight, port, target, ttl } => {
            // Encode name
            matc::mdns::encode_label_compressed(name, out, name_offsets)?;
            // Type SRV = 33
            out.write_u16::<BigEndian>(matc::mdns::TYPE_SRV)?;
            // Class IN = 1
            out.write_u16::<BigEndian>(0x0001)?;
            // TTL
            out.write_u32::<BigEndian>(*ttl)?;
            // RDATA: priority(2) + weight(2) + port(2) + target(label)
            let mut rdata = Vec::new();
            rdata.write_u16::<BigEndian>(*priority)?;
            rdata.write_u16::<BigEndian>(*weight)?;
            rdata.write_u16::<BigEndian>(*port)?;
            matc::mdns::encode_label(target, &mut rdata)?;
            out.write_u16::<BigEndian>(rdata.len() as u16)?;
            out.write_all(&rdata)?;
        }
        DnsRecord::Txt { name, entries, ttl } => {
            // Encode name
            matc::mdns::encode_label_compressed(name, out, name_offsets)?;
            // Type TXT = 16
            out.write_u16::<BigEndian>(matc::mdns::TYPE_TXT)?;
            // Class IN = 1
            out.write_u16::<BigEndian>(0x0001)?;
            // TTL
            out.write_u32::<BigEndian>(*ttl)?;
            // RDATA: concatenated length-prefixed strings
            let mut rdata = Vec::new();
            for entry in entries {
                let bytes = entry.as_bytes();
                if bytes.len() > 255 {
                    anyhow::bail!("TXT entry exceeds 255 bytes: {}", bytes.len());
                }
                rdata.write_u8(bytes.len() as u8)?;
                rdata.write_all(bytes)?;
            }
            out.write_u16::<BigEndian>(rdata.len() as u16)?;
            out.write_all(&rdata)?;
        }
        DnsRecord::A { name, addr, ttl } => {
            // Encode name
            matc::mdns::encode_label_compressed(name, out, name_offsets)?;
            // Type A = 1
            out.write_u16::<BigEndian>(matc::mdns::TYPE_A)?;
            // Class IN = 1
            out.write_u16::<BigEndian>(0x0001)?;
            // TTL
            out.write_u32::<BigEndian>(*ttl)?;
            // RDATA: 4 bytes from IPv4 address
            let octets = addr.octets();
            out.write_u16::<BigEndian>(4)?; // rdlength
            out.write_all(&octets)?;
        }
        DnsRecord::Aaaa { name, addr, ttl } => {
            // Encode name
            matc::mdns::encode_label_compressed(name, out, name_offsets)?;
            // Type AAAA = 28
            out.write_u16::<BigEndian>(matc::mdns::TYPE_AAAA)?;
            // Class IN = 1
            out.write_u16::<BigEndian>(0x0001)?;
            // TTL
            out.write_u32::<BigEndian>(*ttl)?;
            // RDATA: 16 bytes from IPv6 address
            let octets = addr.octets();
            out.write_u16::<BigEndian>(16)?; // rdlength
            out.write_all(&octets)?;
        }
    }
    Ok(())
}

#[derive(Parser)]
#[command(about = "Send a raw mDNS response packet over UDP multicast")]
struct Args {
    /// Hex-encoded mDNS response packet
    packet_hex: Option<String>,
}

fn sample_response() -> Vec<u8> {
    MdnsResponseBuilder::new()
        // PTR record pointing to the service type
        .add_answer(DnsRecord::Ptr {
            name: "_services._dns-sd._udp.local".to_string(),
            target: "_matter._tcp.local".to_string(),
            ttl: 4500,
        })
        // PTR record pointing to the specific device instance
        .add_answer(DnsRecord::Ptr {
            name: "_matter._tcp.local".to_string(),
            target: "mymatterdevice._matter._tcp.local".to_string(),
            ttl: 120,
        })
        .add_answer(DnsRecord::Ptr {
            name: "_matter._tcp.local".to_string(),
            target: "mymatterdevice2._matter._tcp.local".to_string(),
            ttl: 120,
        })
        // SRV record with the device's host and port
        .add_additional(DnsRecord::Srv {
            name: "mymatterdevice._matter._tcp.local".to_string(),
            priority: 0,
            weight: 0,
            port: 5540,
            target: "mymatterdevice.local".to_string(),
            ttl: 120,
        })
        .add_additional(DnsRecord::Srv {
            name: "mymatterdevice2._matter._tcp.local".to_string(),
            priority: 0,
            weight: 0,
            port: 5540,
            target: "mymatterdevice2.local".to_string(),
            ttl: 120,
        })
        // A record with IPv4 address
        .add_additional(DnsRecord::A {
            name: "mymatterdevice.local".to_string(),
            addr: Ipv4Addr::new(192, 168, 1, 100),
            ttl: 120,
        })
        .add_additional(DnsRecord::A {
            name: "mymatterdevice2.local".to_string(),
            addr: Ipv4Addr::new(192, 168, 1, 101),
            ttl: 120,
        })
        .add_additional(DnsRecord::A {
            name: "mymatterdevice2.local".to_string(),
            addr: Ipv4Addr::new(192, 168, 1, 102),
            ttl: 120,
        })
        // AAAA record with IPv6 address
        .add_additional(DnsRecord::Aaaa {
            name: "mymatterdevice.local".to_string(),
            addr: Ipv6Addr::new(0xfe80, 0, 0, 0, 0x1234, 0x5678, 0xabcd, 0xef00),
            ttl: 120,
        })
        // TXT record with Matter-specific attributes
        .add_additional(DnsRecord::Txt {
            name: "mymatterdevice._matter._tcp.local".to_string(),
            entries: vec![
                "D=840".to_string(),           // Discriminator
                "VP=1234+5678".to_string(),    // Vendor ID + Product ID
                "CM=1".to_string(),            // Commissioning Mode
                "DT=259".to_string(),          // Device Type
            ],
            ttl: 120,
        })
        .add_additional(DnsRecord::Txt {
            name: "mymatterdevice2._matter._tcp.local".to_string(),
            entries: vec![
                "D=840".to_string(),           // Discriminator
                "VP=1234+5678".to_string(),    // Vendor ID + Product ID
                "CM=1".to_string(),            // Commissioning Mode
                "DT=259".to_string(),          // Device Type
            ],
            ttl: 120,
        })
        .encode().unwrap()
}

fn main() -> Result<()> {
    let args = Args::parse();


    let data = {
        if let Some(ref hex) = args.packet_hex {
            hex::decode(hex).unwrap()
        } else {
            // Build a sample mDNS response if no hex packet is provided
            sample_response()
        }
    };

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    socket.bind(&SocketAddr::from(([0, 0, 0, 0], 5353)).into())?;

    let std_socket: UdpSocket = socket.into();
    let dest: SocketAddr = "224.0.0.251:5353".parse()?;
    let sent = std_socket.send_to(&data, dest)?;

    println!("Sent {sent} bytes to {dest}");
    Ok(())
}
