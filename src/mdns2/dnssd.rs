//! DNS-SD (DNS Service Discovery): service registration, record building, query matching.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use byteorder::{BigEndian, WriteBytesExt};

use crate::mdns;

/// Description of a local service to advertise via mDNS.
#[derive(Debug, Clone)]
pub struct ServiceRegistration {
    pub service_type: String,
    pub instance_name: String,
    pub port: u16,
    pub hostname: String,
    pub txt_records: Vec<(String, String)>,
    pub ttl: u32,
}

/// Events emitted by the mDNS service to the user.
#[derive(Debug, Clone)]
pub enum MdnsEvent {
    ServiceDiscovered {
        name: String,
        target: String,
        records: Vec<mdns::RR>,
    },
    ServiceExpired {
        name: String,
        rtype: u16,
    },
}

pub(super) struct PeriodicQuery {
    pub label: String,
    pub qtype: u16,
    pub interval: Duration,
    pub last_sent: Instant,
}

/// Build the set of DNS records for a service registration.
pub(super) fn build_service_records(
    reg: &ServiceRegistration,
    ips_v4: &[Ipv4Addr],
    ips_v6: &[Ipv6Addr],
) -> Vec<mdns::RR> {
    let mut records = Vec::new();
    let instance_full = format!("{}.{}", reg.instance_name, reg.service_type);

    // PTR
    records.push(mdns::RR {
        name: format!("{}.", reg.service_type),
        typ: mdns::TYPE_PTR,
        class: 1,
        ttl: reg.ttl,
        rdata: {
            let mut buf = Vec::new();
            let _ = mdns::encode_label(&instance_full, &mut buf);
            buf
        },
        target: None,
        data: mdns::RRData::PTR(instance_full.clone()),
    });

    // SRV
    let mut srv_rdata = Vec::new();
    let _ = srv_rdata.write_u16::<BigEndian>(0); // priority
    let _ = srv_rdata.write_u16::<BigEndian>(0); // weight
    let _ = srv_rdata.write_u16::<BigEndian>(reg.port);
    let _ = mdns::encode_label(reg.hostname.trim_end_matches('.'), &mut srv_rdata);
    records.push(mdns::RR {
        name: format!("{}.", instance_full),
        typ: mdns::TYPE_SRV,
        class: 1,
        ttl: reg.ttl,
        rdata: srv_rdata,
        target: Some(format!("{}.", reg.hostname.trim_end_matches('.'))),
        data: mdns::RRData::SRV {
            priority: 0,
            weight: 0,
            port: reg.port,
            target: format!("{}.", reg.hostname.trim_end_matches('.')),
        },
    });

    // TXT
    let mut txt_rdata = Vec::new();
    for (k, v) in &reg.txt_records {
        let entry = format!("{}={}", k, v);
        let _ = txt_rdata.write_u8(entry.len() as u8);
        txt_rdata.extend_from_slice(entry.as_bytes());
    }
    if txt_rdata.is_empty() {
        txt_rdata.push(0); // RFC 6763: empty TXT record has single zero-length byte
    }
    records.push(mdns::RR {
        name: format!("{}.", instance_full),
        typ: mdns::TYPE_TXT,
        class: 1,
        ttl: reg.ttl,
        rdata: txt_rdata,
        target: None,
        data: mdns::RRData::TXT(
            reg.txt_records
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect(),
        ),
    });


    for ip in ips_v4 {
        records.push(mdns::RR {
            name: format!("{}.", reg.hostname.trim_end_matches('.')),
            typ: mdns::TYPE_A,
            class: 1,
            ttl: reg.ttl,
            rdata: ip.octets().to_vec(),
            target: None,
            data: mdns::RRData::A(*ip),
        });
    }


    for ip in ips_v6 {
        records.push(mdns::RR {
            name: format!("{}.", reg.hostname.trim_end_matches('.')),
            typ: mdns::TYPE_AAAA,
            class: 1,
            ttl: reg.ttl,
            rdata: ip.octets().to_vec(),
            target: None,
            data: mdns::RRData::AAAA(*ip),
        });
    }

    records
}

/// Find registered services that match an incoming query and build response records.
pub(super) fn find_matching_services(
    query_name: &str,
    query_type: u16,
    services: &[ServiceRegistration],
    ips_v4: &[Ipv4Addr],
    ips_v6: &[Ipv6Addr],
) -> (Vec<mdns::RR>, Vec<mdns::RR>) {
    let mut answers = Vec::new();
    let mut additional = Vec::new();

    let qname = query_name.to_lowercase();
    let qname = qname.trim_end_matches('.');

    for reg in services {
        let svc_type = reg.service_type.trim_end_matches('.').to_lowercase();
        let instance_full = format!("{}.{}", reg.instance_name.to_lowercase(), svc_type);

        let all_records = build_service_records(reg, ips_v4, ips_v6);
        let is_any = query_type == mdns::QTYPE_ANY;

        // Query for service type - return PTR as answer, rest as additional
        if qname == svc_type {
            for r in &all_records {
                let rname = r.name.trim_end_matches('.').to_lowercase();
                if rname == svc_type && (is_any || r.typ == mdns::TYPE_PTR || r.typ == query_type) {
                    answers.push(r.clone());
                } else {
                    additional.push(r.clone());
                }
            }
        }
        // Query for specific instance - return SRV/TXT as answer, A/AAAA as additional
        else if qname == instance_full {
            for r in &all_records {
                let rname = r.name.trim_end_matches('.').to_lowercase();
                if rname == instance_full && (is_any || r.typ == query_type) {
                    answers.push(r.clone());
                } else if r.typ == mdns::TYPE_A || r.typ == mdns::TYPE_AAAA {
                    additional.push(r.clone());
                }
            }
        }
        // Query for hostname - return A/AAAA as answer
        else if qname == reg.hostname.trim_end_matches('.').to_lowercase() {
            for r in &all_records {
                if (r.typ == mdns::TYPE_A || r.typ == mdns::TYPE_AAAA)
                    && (is_any || r.typ == query_type)
                {
                    answers.push(r.clone());
                }
            }
        }
    }

    (answers, additional)
}

