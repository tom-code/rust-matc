//! minimal mDNS service with continuous discovery, record caching, and service registration.
//!
//! this provides a long-running service that:
//! - Runs continuous discovery with periodic re-queries
//! - Caches discovered records with TTL-based expiration
//! - Registers local services and responds to incoming mDNS queries

mod dnssd;
mod protocol;

pub use dnssd::{MdnsEvent, ServiceRegistration};
pub use protocol::{CachedRecord, RecordCache};

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio_util::sync::CancellationToken;

use crate::mdns;
use dnssd::{PeriodicQuery, build_service_records, find_matching_services};
use protocol::{
    MDNS_ADDR_V4, MDNS_ADDR_V6, McastSocket, SendCommand, build_response,
    create_multicast_socket_v4, create_multicast_socket_v6, get_local_ips, send_loop,
};

struct MdnsServiceInner {
    cache: RecordCache,
    queries: Vec<PeriodicQuery>,
    services: Vec<ServiceRegistration>,
    local_ips_v4: Vec<Ipv4Addr>,
    local_ips_v6: Vec<Ipv6Addr>,
}

/// Long-running mDNS service with discovery, caching, and service registration.
pub struct MdnsService {
    inner: Arc<Mutex<MdnsServiceInner>>,
    send_tx: UnboundedSender<SendCommand>,
    cancel: CancellationToken,
}

async fn recv_loop(
    socket: Arc<UdpSocket>,
    inner: Arc<Mutex<MdnsServiceInner>>,
    send_tx: UnboundedSender<SendCommand>,
    event_tx: UnboundedSender<MdnsEvent>,
    cancel: CancellationToken,
) {
    let mut buf = vec![0u8; 9000];
    loop {
        let (n, addr) = tokio::select! {
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok(v) => v,
                    Err(e) => {
                        log::debug!("mdns2 recv error: {}", e);
                        continue;
                    }
                }
            }
            _ = cancel.cancelled() => return,
        };

        let data = &buf[..n];
        let msg = match mdns::parse_dns(data, addr) {
            Ok(m) => m,
            Err(e) => {
                log::trace!("mdns2: failed to parse packet from {}: {:?}", addr, e);
                continue;
            }
        };

        let is_response = msg.flags & 0x8000 != 0;

        if is_response {
            // Ingest all records into cache
            let mut state = inner.lock().await;
            let all_records: Vec<mdns::RR> = msg
                .answers
                .iter()
                .chain(msg.additional.iter())
                .cloned()
                .collect();

            let mut new_ptr_records = Vec::new();
            for rr in &all_records {
                state.cache.ingest(rr);
                if rr.typ == mdns::TYPE_PTR {
                    if let mdns::RRData::PTR(ref target) = rr.data {
                        log::debug!("New PTR record: {} -> {}", rr.name, target);
                        new_ptr_records.push((rr.name.clone(), target.clone()));
                    }
                }
            }
            for (name, target) in new_ptr_records {
                let _ = event_tx.send(MdnsEvent::ServiceDiscovered {
                    name,
                    target,
                    records: all_records.clone(),
                });
            }
        } else {
            // Incoming query — check if we have matching local services
            let state = inner.lock().await;
            if state.services.is_empty() {
                continue;
            }
            let mut all_answers = Vec::new();
            let mut all_additional = Vec::new();
            for q in &msg.queries {
                let (ans, add) = find_matching_services(
                    &q.name,
                    q.typ,
                    &state.services,
                    &state.local_ips_v4,
                    &state.local_ips_v6,
                );
                all_answers.extend(ans);
                all_additional.extend(add);
            }
            drop(state);

            if !all_answers.is_empty() {
                if let Ok(packet) = build_response(&all_answers, &all_additional) {
                    let _ = send_tx.send(SendCommand::Multicast(packet));
                }
            }
        }
    }
}

async fn periodic_loop(
    inner: Arc<Mutex<MdnsServiceInner>>,
    send_tx: UnboundedSender<SendCommand>,
    event_tx: UnboundedSender<MdnsEvent>,
    cancel: CancellationToken,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = interval.tick() => {}
            _ = cancel.cancelled() => return,
        }

        let mut state = inner.lock().await;

        // Evict expired cache entries
        let expired = state.cache.evict_expired();
        for (name, rtype) in expired {
            let _ = event_tx.send(MdnsEvent::ServiceExpired { name, rtype });
        }

        // Send due queries
        let now = Instant::now();
        let mut packets = Vec::new();
        for q in &mut state.queries {
            if now.duration_since(q.last_sent) >= q.interval {
                if let Ok(pkt) = mdns::create_query(&q.label, q.qtype) {
                    packets.push(pkt);
                }
                q.last_sent = now;
            }
        }
        drop(state);

        for pkt in packets {
            let _ = send_tx.send(SendCommand::Multicast(pkt));
        }

        // Refresh local IPs periodically (cheap operation)
        let (v4, v6) = get_local_ips();
        let mut state = inner.lock().await;
        state.local_ips_v4 = v4;
        state.local_ips_v6 = v6;
    }
}

impl MdnsService {
    /// Create a new mDNS service. Returns the service handle and a receiver for events.
    pub async fn new() -> Result<(Arc<Self>, UnboundedReceiver<MdnsEvent>)> {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (send_tx, send_rx) = mpsc::unbounded_channel();
        let cancel = CancellationToken::new();

        let (v4, v6) = get_local_ips();
        let inner = Arc::new(Mutex::new(MdnsServiceInner {
            cache: RecordCache::new(),
            queries: Vec::new(),
            services: Vec::new(),
            local_ips_v4: v4,
            local_ips_v6: v6,
        }));

        // Create sockets
        let mut mcast_sockets: Vec<McastSocket> = Vec::new();

        // IPv4
        match create_multicast_socket_v4() {
            Ok(std_sock) => match UdpSocket::from_std(std_sock) {
                Ok(s) => mcast_sockets.push(McastSocket {
                    sock: Arc::new(s),
                    multicast_addr: MDNS_ADDR_V4,
                }),
                Err(e) => log::warn!("mdns2: failed to wrap v4 socket: {}", e),
            },
            Err(e) => log::warn!("mdns2: failed to create v4 socket: {}", e),
        }

        // IPv6 — one per interface
        if let Ok(ifaces) = if_addrs::get_if_addrs() {
            let mut seen_indices = std::collections::HashSet::new();
            for iface in ifaces {
                if !iface.ip().is_ipv6() {
                    continue;
                }
                if let Some(idx) = iface.index {
                    if !seen_indices.insert(idx) {
                        continue;
                    }
                    match create_multicast_socket_v6(idx) {
                        Ok(std_sock) => match UdpSocket::from_std(std_sock) {
                            Ok(s) => mcast_sockets.push(McastSocket {
                                sock: Arc::new(s),
                                multicast_addr: MDNS_ADDR_V6,
                            }),
                            Err(e) => {
                                log::debug!("mdns2: failed to wrap v6 socket idx={}: {}", idx, e)
                            }
                        },
                        Err(e) => {
                            log::debug!("mdns2: failed to create v6 socket idx={}: {}", idx, e)
                        }
                    }
                }
            }
        }

        if mcast_sockets.is_empty() {
            anyhow::bail!("mdns2: no sockets could be created");
        }

        // Spawn recv loops (one per socket)
        for ms in &mcast_sockets {
            let sock = ms.sock.clone();
            let inner = inner.clone();
            let send_tx = send_tx.clone();
            let event_tx = event_tx.clone();
            let cancel = cancel.child_token();
            tokio::spawn(async move {
                recv_loop(sock, inner, send_tx, event_tx, cancel).await;
            });
        }

        // Spawn periodic loop
        {
            let inner = inner.clone();
            let send_tx = send_tx.clone();
            let event_tx = event_tx.clone();
            let cancel = cancel.child_token();
            tokio::spawn(async move {
                periodic_loop(inner, send_tx, event_tx, cancel).await;
            });
        }

        // Spawn send loop
        {
            let cancel = cancel.child_token();
            tokio::spawn(async move {
                send_loop(mcast_sockets, send_rx, cancel).await;
            });
        }

        let service = Arc::new(MdnsService {
            inner,
            send_tx,
            cancel,
        });

        Ok((service, event_rx))
    }

    /// Add a periodic query. The query will be sent immediately, then every interval.
    pub async fn add_query(&self, label: &str, qtype: u16, interval: Duration) {
        let mut state = self.inner.lock().await;
        // Send immediately
        let sent_at = Instant::now();
        if let Ok(pkt) = mdns::create_query(label, qtype) {
            let _ = self.send_tx.send(SendCommand::Multicast(pkt));
        }
        state.queries.push(PeriodicQuery {
            label: label.to_owned(),
            qtype,
            interval,
            last_sent: sent_at,
        });
    }

    /// Remove a periodic query by label.
    pub async fn remove_query(&self, label: &str) {
        let mut state = self.inner.lock().await;
        state.queries.retain(|q| q.label != label);
    }

    /// Register a local service to be advertised.
    pub async fn register_service(&self, reg: ServiceRegistration) {
        let mut state = self.inner.lock().await;
        state.services.push(reg);
    }

    /// Unregister a local service. Sends a goodbye (TTL=0) for the service records.
    pub async fn unregister_service(&self, instance: &str, service_type: &str) {
        let mut state = self.inner.lock().await;
        let idx = state
            .services
            .iter()
            .position(|s| s.instance_name == instance && s.service_type == service_type);
        if let Some(idx) = idx {
            let reg = state.services.remove(idx);
            // Build goodbye records (TTL=0)
            let mut goodbye_records =
                build_service_records(&reg, &state.local_ips_v4, &state.local_ips_v6);
            for rr in &mut goodbye_records {
                rr.ttl = 0;
            }
            drop(state);
            if let Ok(pkt) = build_response(&goodbye_records, &[]) {
                let _ = self.send_tx.send(SendCommand::Multicast(pkt));
            }
        }
    }

    /// Send a gratuitous announcement of all registered services.
    pub async fn announce(&self) {
        let state = self.inner.lock().await;
        let mut all_answers = Vec::new();
        let mut all_additional = Vec::new();
        for reg in &state.services {
            let records = build_service_records(reg, &state.local_ips_v4, &state.local_ips_v6);
            // PTR goes as answer, everything else as additional
            for r in records {
                if r.typ == mdns::TYPE_PTR {
                    all_answers.push(r);
                } else {
                    all_additional.push(r);
                }
            }
        }
        drop(state);

        if !all_answers.is_empty() {
            if let Ok(pkt) = build_response(&all_answers, &all_additional) {
                let _ = self.send_tx.send(SendCommand::Multicast(pkt));
            }
        }
    }

    /// Lookup cached records by name and type.
    pub async fn lookup(&self, name: &str, qtype: u16) -> Vec<mdns::RR> {
        let state = self.inner.lock().await;
        if qtype == mdns::QTYPE_ANY {
            state.cache.lookup_name(name)
        } else {
            state.cache.lookup(name, qtype)
        }
    }

    pub async fn active_lookup(&self, name: &str, qtype: u16) {
        if let Ok(pkt) = mdns::create_query(name, qtype) {
            let _ = self.send_tx.send(SendCommand::Multicast(pkt));
        }
    }

    /// Shut down all background tasks.
    pub fn shutdown(&self) {
        self.cancel.cancel();
    }
}

impl Drop for MdnsService {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
