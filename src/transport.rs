// Simple UDP transport abstraction that multiplexes datagrams by remote address
// into per-connection mpsc channels. Each Connection is a logical association
// identified solely by the peer's socket address string.

/// Returned by [`Connection::receive`] when the underlying mpsc channel has been
/// closed (e.g. because the same remote address was re-registered via
/// [`Transport::create_connection`]). Callers can detect this via
/// `anyhow::Error::downcast_ref::<ConnectionClosed>()` and bail immediately
/// instead of spinning on retransmit.
#[derive(Debug)]
pub struct ConnectionClosed;

impl std::fmt::Display for ConnectionClosed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "connection closed")
    }
}

impl std::error::Error for ConnectionClosed {}

use anyhow::{Context, Result};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{net::UdpSocket, sync::Mutex};

/// Normalize a peer address string so that its address family matches the
/// local socket. This canonical form is used both as the connection map key
/// and as the destination for `send_to`, so inbound and outbound paths agree
/// without per-packet conversion.
///
/// * V6 socket + V4 peer  -> V4-mapped V6 (`[::ffff:a.b.c.d]:port`), needed
///   because the kernel rejects cross-family `sendto` on AF_INET6.
/// * V4 socket + V4-mapped V6 peer -> plain V4.
/// * Other combinations are returned unchanged (real V6 on a V4 socket will
///   fail at `send_to`, which is the correct behavior).
fn normalize_remote_for_socket(socket: &UdpSocket, remote: &str) -> String {
    let Ok(parsed) = remote.parse::<SocketAddr>() else {
        return remote.to_owned();
    };
    let Ok(local) = socket.local_addr() else {
        return parsed.to_string();
    };
    let normalized = match (local.is_ipv6(), parsed) {
        (true, SocketAddr::V4(v4)) => {
            let mapped = v4.ip().to_ipv6_mapped();
            SocketAddr::new(IpAddr::V6(mapped), v4.port())
        }
        (false, SocketAddr::V6(v6)) => {
            if let Some(v4) = v6.ip().to_ipv4_mapped() {
                SocketAddr::new(IpAddr::V4(v4), v6.port())
            } else {
                parsed
            }
        }
        _ => parsed,
    };
    normalized.to_string()
}

/// Transport-agnostic connection: send and receive raw Matter messages.
///
/// Implement this for UDP ([`Connection`]) and BTP ([`crate::btp::BtpConnection`]).
#[async_trait::async_trait]
pub trait ConnectionTrait: Send + Sync {
    async fn send(&self, data: &[u8]) -> Result<()>;
    async fn receive(&self, timeout: Duration) -> Result<Vec<u8>>;
    /// True for transports (BTP) that guarantee delivery so Matter-layer MRP
    /// retransmit should be suppressed.  Default: false (UDP).
    fn is_reliable(&self) -> bool { false }
    /// Peer MRP intervals used for retransmission timing. Defaults to spec
    /// defaults unless overridden via [`ConnectionTrait::set_mrp_params`].
    fn mrp_params(&self) -> crate::mrp::MrpParameters { Default::default() }
    /// Set peer MRP intervals (typically from its mDNS SII/SAI/SAT TXT records).
    fn set_mrp_params(&self, _params: crate::mrp::MrpParameters) {}
    /// Time since the last message was received from the peer, if any.
    /// Used to select the active vs idle retransmission interval.
    fn last_received_elapsed(&self) -> Option<Duration> { None }
}

#[derive(Debug, Clone)]
struct ConnectionInfo {
    sender: tokio::sync::mpsc::Sender<Vec<u8>>,
    generation: u64,
}

/// Shared transport holding:
/// * a single UDP socket
/// * a map of remote_addr -> channel sender
/// * a task to read incoming datagrams and dispatch them
/// * a task to remove connection entries when Connections drop
pub struct Transport {
    socket: Arc<UdpSocket>,
    connections: Mutex<HashMap<String, ConnectionInfo>>,
    remove_channel_sender: tokio::sync::mpsc::UnboundedSender<(String, u64)>,
    next_generation: AtomicU64,
    stop_receive_token: tokio_util::sync::CancellationToken,
}

/// Logical connection bound to a remote UDP address. Receiving is done by
/// reading from an mpsc channel populated by the Transport reader task.
pub struct Connection {
    transport: Arc<Transport>,
    remote_address: String,
    /// scope_id (interface zone) for a link-local IPv6 peer, from mDNS.
    scope_id: Option<u32>,
    receiver: Mutex<tokio::sync::mpsc::Receiver<Vec<u8>>>,
    generation: u64,
    mrp: std::sync::Mutex<crate::mrp::MrpParameters>,
    created: tokio::time::Instant,
    /// Milliseconds since `created` of the last received datagram; u64::MAX = never.
    last_rx_ms: AtomicU64,
}

impl Transport {
    async fn read_from_socket_loop(
        socket: Arc<UdpSocket>,
        stop_receive_token: tokio_util::sync::CancellationToken,
        self_weak: std::sync::Weak<Transport>,
    ) -> Result<()> {
        loop {
            let mut buf = vec![0u8; 2048];
            let recv_result = {
                tokio::select! {
                    recv_resp = socket.recv_from(&mut buf) => recv_resp,
                    _ = stop_receive_token.cancelled() => break
                }
            };
            let (n, addr) = match recv_result {
                Ok(r) => r,
                Err(e) => {
                    log::debug!("transport recv error (ignored): {:?}", e);
                    continue;
                }
            };
            buf.resize(n, 0);
            let self_strong = self_weak
                .upgrade()
                .context("weakpointer to self is gone - just stop")?;
            let cons = self_strong.connections.lock().await;
            if let Some(c) = cons.get(&scopeless_key(addr)) {
                _ = c.sender.send(buf).await;
            }
        }
        Ok(())
    }

    async fn read_from_delete_queue_loop(
        mut remove_channel_receiver: tokio::sync::mpsc::UnboundedReceiver<(String, u64)>,
        self_weak: std::sync::Weak<Transport>,
    ) -> Result<()> {
        loop {
            let to_remove = remove_channel_receiver.recv().await;
            match to_remove {
                Some((addr, _gen)) if addr.is_empty() => {
                    // Empty address is the shutdown sentinel.
                    break;
                }
                Some((addr, gen)) => {
                    let self_strong = self_weak
                        .upgrade()
                        .context("weak to self is gone - just stop")?;
                    let mut cons = self_strong.connections.lock().await;
                    // Only remove if the entry still belongs to this Connection.
                    // A concurrent create_connection for the same address inserts a
                    // newer generation, so the stale remove becomes a no-op.
                    if cons.get(&addr).map(|c| c.generation) == Some(gen) {
                        cons.remove(&addr);
                    }
                }
                None => break, // Sender dropped => shutdown
            }
        }
        Ok(())
    }

    /// Bind a UDP socket and spawn background tasks.
    pub async fn new(local: &str) -> Result<Arc<Self>> {
        let socket = UdpSocket::bind(local).await?;
        let (remove_channel_sender, remove_channel_receiver) =
            tokio::sync::mpsc::unbounded_channel();
        let stop_receive_token = tokio_util::sync::CancellationToken::new();
        let stop_receive_token_child = stop_receive_token.child_token();
        let o = Arc::new(Self {
            socket: Arc::new(socket),
            connections: Mutex::new(HashMap::new()),
            remove_channel_sender,
            next_generation: AtomicU64::new(1),
            stop_receive_token,
        });
        let self_weak = Arc::downgrade(&o.clone());
        let socket = o.socket.clone();
        tokio::spawn(async move {
            _ = Self::read_from_socket_loop(socket, stop_receive_token_child, self_weak).await;
        });
        let self_weak = Arc::downgrade(&o.clone());
        tokio::spawn(async move {
            _ = Self::read_from_delete_queue_loop(remove_channel_receiver, self_weak).await;
        });
        Ok(o)
    }

    /// Create (or replace) a logical connection entry for the given remote address.
    pub async fn create_connection(self: &Arc<Self>, remote: &str) -> Arc<dyn ConnectionTrait> {
        let (remote, scope_id) = split_scope(remote);
        let remote = normalize_remote_for_socket(&self.socket, &remote);
        let mut clock = self.connections.lock().await;
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
        let (sender, receiver) = tokio::sync::mpsc::channel(32);
        clock.insert(remote.to_owned(), ConnectionInfo { sender, generation });
        Arc::new(Connection {
            transport: self.clone(),
            remote_address: remote,
            scope_id,
            receiver: Mutex::new(receiver),
            generation,
            mrp: std::sync::Mutex::new(Default::default()),
            created: tokio::time::Instant::now(),
            last_rx_ms: AtomicU64::new(u64::MAX),
        })
    }
}

/// True for IPv6 link-local (fe80::/10).
fn is_link_local_v6(ip: &std::net::Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

/// Split the zone out of `[fe80::...%<idx>]:port`: returns the zone-less address and the scope_id.
fn split_scope(remote: &str) -> (String, Option<u32>) {
    if let Some(pct) = remote.find('%') {
        let (head, tail) = remote.split_at(pct);
        let after = &tail[1..];
        let digits: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
        let rest = &after[digits.len()..];
        if let Ok(idx) = digits.parse::<u32>() {
            return (format!("{head}{rest}"), Some(idx));
        }
    }
    (remote.to_owned(), None)
}

/// Connection key without the zone.
fn scopeless_key(addr: SocketAddr) -> String {
    match addr {
        // SocketAddrV6 is Copy: `mut v6` copies, so the original addr is untouched.
        SocketAddr::V6(mut v6) if v6.scope_id() != 0 => {
            v6.set_scope_id(0);
            v6.to_string()
        }
        _ => addr.to_string(),
    }
}

impl Connection {
    /// Send a datagram to the remote address.
    pub async fn send(&self, data: &[u8]) -> Result<()> {
        let socket = &self.transport.socket;

        // For link-local IPv6 attach the scope_id (interface zone from mDNS).
        if let (Some(scope), Ok(SocketAddr::V6(v6))) =
            (self.scope_id, self.remote_address.parse::<SocketAddr>())
        {
            if is_link_local_v6(v6.ip()) {
                let target = std::net::SocketAddrV6::new(*v6.ip(), v6.port(), v6.flowinfo(), scope);
                socket.send_to(data, SocketAddr::V6(target)).await?;
                return Ok(());
            }
        }

        socket.send_to(data, &self.remote_address).await?;
        Ok(())
    }
    /// Receive the next datagram for this connection (with timeout).
    ///
    /// Returns `Err(ConnectionClosed)` (detectable via `downcast_ref`) when the
    /// channel is permanently closed, distinct from a normal receive timeout.
    pub async fn receive(&self, timeout: Duration) -> Result<Vec<u8>> {
        let mut ch = self.receiver.lock().await;
        let rec_future = ch.recv();
        let with_timeout = tokio::time::timeout(timeout, rec_future);
        match with_timeout.await {
            Err(_elapsed) => Err(anyhow::anyhow!("receive timeout")),
            Ok(None) => Err(anyhow::Error::new(ConnectionClosed)),
            Ok(Some(v)) => {
                self.last_rx_ms
                    .store(self.created.elapsed().as_millis() as u64, Ordering::Relaxed);
                Ok(v)
            }
        }
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        _ = self.remove_channel_sender.send(("".to_owned(), 0));
        self.stop_receive_token.cancel();
    }
}

#[async_trait::async_trait]
impl ConnectionTrait for Connection {
    async fn send(&self, data: &[u8]) -> Result<()> {
        self.send(data).await
    }
    async fn receive(&self, timeout: Duration) -> Result<Vec<u8>> {
        self.receive(timeout).await
    }
    fn mrp_params(&self) -> crate::mrp::MrpParameters {
        *self.mrp.lock().unwrap()
    }
    fn set_mrp_params(&self, params: crate::mrp::MrpParameters) {
        *self.mrp.lock().unwrap() = params;
    }
    fn last_received_elapsed(&self) -> Option<Duration> {
        let ms = self.last_rx_ms.load(Ordering::Relaxed);
        if ms == u64::MAX {
            return None;
        }
        Some(self.created.elapsed().saturating_sub(Duration::from_millis(ms)))
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        _ = self
            .transport
            .remove_channel_sender
            .send((self.remote_address.clone(), self.generation));
    }
}

