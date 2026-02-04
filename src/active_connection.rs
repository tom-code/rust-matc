use anyhow::{Context, Result};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio_util::sync::CancellationToken;

use crate::{messages::{self, Message, ProtocolMessageHeader}, session::Session, transport};

const RECEIVE_TIMEOUT: Duration = Duration::from_secs(1);
const RETRANSMIT_THRESHOLD: Duration = Duration::from_secs(3);
const MAX_RETRANSMIT_AGE: Duration = Duration::from_secs(10);
const MAX_CACHED_COUNTERS: usize = 32;

/// Tracks an unacknowledged message pending retransmit.
struct UnackedMessage {
    /// Encoded message bytes to retransmit
    data: Vec<u8>,
    /// When the message was first sent (for max age check)
    original_time: Instant,
    /// When the message was last sent (for retransmit interval)
    last_sent: Instant,
    /// Associated exchange ID for timeout signaling
    exchange_id: Option<u16>,
}

/// Bounded set for tracking received message counters to detect duplicates
struct ReceivedCounters {
    set: HashSet<u32>,
    order: VecDeque<u32>,
    max_size: usize,
}

impl ReceivedCounters {
    fn new(max_size: usize) -> Self {
        Self {
            set: HashSet::new(),
            order: VecDeque::new(),
            max_size,
        }
    }

    /// Returns true if counter was new (not a duplicate)
    fn insert(&mut self, counter: u32) -> bool {
        if !self.set.insert(counter) {
            return false; // duplicate
        }
        self.order.push_back(counter);

        // Evict oldest if over limit
        while self.order.len() > self.max_size {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }
        true
    }

    /*fn remove(&mut self, counter: &u32) {
        self.set.remove(counter);
    }*/
}

/// Active connection with background read task for continuous message handling.
pub struct ActiveConnection {
    transport_conn: Arc<transport::Connection>,
    session: Arc<Session>,

    /// Routing responses to waiting callers by exchange ID
    pending_exchanges: Arc<std::sync::Mutex<HashMap<u16, oneshot::Sender<Message>>>>,

    /// Retransmit tracking
    unacked: Arc<Mutex<HashMap<u32, UnackedMessage>>>,

    /// Duplicate detection
    //received_counters: Arc<std::sync::Mutex<ReceivedCounters>>,

    /// Events channel (unsolicited messages)
    event_rx: Mutex<mpsc::Receiver<Message>>,
    //event_tx: mpsc::Sender<Message>,

    cancel: CancellationToken,
}

impl ActiveConnection {
    /// Create from transport connection and authenticated session.
    /// Spawns a background task that continuously reads from the connection.
    pub fn new(conn: Arc<transport::Connection>, session: Session) -> Self {
        let (event_tx, event_rx) = mpsc::channel(32);
        let cancel = CancellationToken::new();

        let session = Arc::new(session);
        let pending_exchanges = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let unacked = Arc::new(Mutex::new(HashMap::new()));
        let received_counters = Arc::new(std::sync::Mutex::new(ReceivedCounters::new(MAX_CACHED_COUNTERS)));

        // Spawn background read loop
        let read_loop_conn = conn.clone();
        let read_loop_session = session.clone();
        let read_loop_pending = pending_exchanges.clone();
        let read_loop_unacked = unacked.clone();
        let read_loop_received = received_counters.clone();
        let read_loop_event_tx = event_tx.clone();
        let read_loop_cancel = cancel.clone();

        tokio::spawn(async move {
            connection_read_loop(
                read_loop_conn,
                read_loop_session,
                read_loop_pending,
                read_loop_unacked,
                read_loop_received,
                read_loop_event_tx,
                read_loop_cancel,
            )
            .await;
        });

        Self {
            transport_conn: conn,
            session,
            pending_exchanges,
            unacked,
            //received_counters,
            event_rx: Mutex::new(event_rx),
            //event_tx,
            cancel,
        }
    }

    /// Encode, send and add to retransmit buffer
    async fn send_internal(&self, exchange_id: u16, data: &[u8]) -> Result<()> {
        let encoded = self.session.encode_message(data)?;
        self.track_sent(&encoded, Some(exchange_id)).await;
        if let Err(e) = self.transport_conn.send(&encoded).await {
            log::debug!("error sending message on exchange {}: {:?}", exchange_id, e);
            if let Ok((header, _)) = messages::MessageHeader::decode(&encoded) {
                self.unacked.lock().await.remove(&header.message_counter);
            }
            return Err(e);
        }
        Ok(())
    }
    
    /// Send request and wait for response on specific exchange.
    pub async fn request(&self, exchange_id: u16, data: &[u8]) -> Result<Message> {
        let (tx, rx) = oneshot::channel();

        // Register for response
        {
            let mut pending = self.pending_exchanges.lock().unwrap();
            pending.insert(exchange_id, tx);
        }

        // Encode, send and track for retransmit
        if let Err(e) = self.send_internal(exchange_id, data).await {
            // Sending failed - clean up pending
            log::debug!("error sending request on exchange {}: {:?}; cleanp up retransmit/exchange maps", exchange_id, e);
            let mut pending = self.pending_exchanges.lock().unwrap();
            pending.remove(&exchange_id);
            return Err(e);
        }

        // Wait for response
        rx.await.context("request timed out - no response received")
    }

    /*
    /// Send without registering for response (fire-and-forget with retransmit).
    pub async fn send(&self, data: &[u8]) -> Result<()> {
        let encoded = self.session.encode_message(data)?;
        self.track_sent(&encoded, None).await;
        self.transport_conn.send(&encoded).await?;
        Ok(())
    }*/

    /// Receive next event. Returns None when connection is closed.
    pub async fn recv_event(&self) -> Option<Message> {
        let mut rx = self.event_rx.lock().await;
        rx.recv().await
    }

    /// Try receive event without blocking.
    pub fn try_recv_event(&self) -> Option<Message> {
        // Note: This requires trying to lock, so it may not always succeed
        match self.event_rx.try_lock() {
            Ok(mut rx) => rx.try_recv().ok(),
            Err(_) => None,
        }
    }

    /// Track sent message for retransmit with optional exchange_id for result signaling.
    async fn track_sent(&self, encoded: &[u8], exchange_id: Option<u16>) {
        if let Ok((header, _)) = messages::MessageHeader::decode(encoded) {
            let mut unacked = self.unacked.lock().await;
            let now = Instant::now();
            unacked.insert(header.message_counter, UnackedMessage {
                data: encoded.to_vec(),
                original_time: now,
                last_sent: now,
                exchange_id,
            });
            log::trace!("tracking sent message counter:{}", header.message_counter);
        }
    }
}

impl Drop for ActiveConnection {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

async fn connection_read_loop(
    transport_conn: Arc<transport::Connection>,
    session: Arc<Session>,
    pending_exchanges: Arc<std::sync::Mutex<HashMap<u16, oneshot::Sender<Message>>>>,
    unacked: Arc<Mutex<HashMap<u32, UnackedMessage>>>,
    received_counters: Arc<std::sync::Mutex<ReceivedCounters>>,
    event_tx: mpsc::Sender<Message>,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,

            result = transport_conn.receive(RECEIVE_TIMEOUT) => {
                match result {
                    Ok(data) => {
                        log::trace!("received {} bytes", data.len());
                        if let Err(e) = process_incoming(
                            &data,
                            &session,
                            &transport_conn,
                            &pending_exchanges,
                            &unacked,
                            &received_counters,
                            &event_tx,
                        ).await {
                            log::debug!("error processing incoming message: {:?}", e);
                        }
                    }
                    Err(_) => {
                        log::debug!("receive timeout");
                        // Timeout - check for retransmit
                        check_retransmit(&transport_conn, &unacked, &pending_exchanges).await;
                    }
                }
            }
        }
    }
}

async fn process_incoming(
    data: &[u8],
    session: &Arc<Session>,
    transport_conn: &Arc<transport::Connection>,
    pending_exchanges: &Arc<std::sync::Mutex<HashMap<u16, oneshot::Sender<Message>>>>,
    unacked: &Arc<Mutex<HashMap<u32, UnackedMessage>>>,
    received_counters: &Arc<std::sync::Mutex<ReceivedCounters>>,
    event_tx: &mpsc::Sender<Message>,
) -> Result<()> {
    // 1. Decode via session (decrypt if keys set)
    log::trace!("received raw data: {:x?}", data);
    let decoded_data = session.decode_message(data);
    let decoded_data = match decoded_data {
        Ok(d) => d,
        Err(e) => {
            log::debug!("failed to decode incoming message: {}", e.to_string());
            return Ok(());
        }
    };

    // 2. Parse Message
    let message = Message::decode(&decoded_data)?;
    log::trace!("received message {:?}", message);

    // 3. Handle ACK flag -> remove from unacked
    if message.protocol_header.exchange_flags & ProtocolMessageHeader::FLAG_ACK != 0 {
        let mut unacked_lock = unacked.lock().await;
        unacked_lock.remove(&message.protocol_header.ack_counter);
        log::trace!(
            "received ack for counter:{}",
            message.protocol_header.ack_counter
        );
    }

    // 4. Duplicate check
    let is_new = {
        let mut received = received_counters.lock().unwrap();
        received.insert(message.message_header.message_counter)
    };

    if !is_new {
        // Send ACK for duplicate (lost ACK may be reason for duplicate)
        send_ack(session, transport_conn, &message).await?;
        log::trace!(
            "dropping duplicate message exchange:{} counter:{}",
            message.protocol_header.exchange_id,
            message.message_header.message_counter
        );
        return Ok(());
    }

    // 5. Send ACK for new messages
    if message.protocol_header.exchange_flags & ProtocolMessageHeader::FLAG_RELIABILITY != 0 {
        // Only send ACK for messages that do have the reliability flag set
        send_ack(session, transport_conn, &message).await?;
    }
    //send_ack(session, transport_conn, &message).await?;

    // 6. Skip standalone ACK messages
    if message.protocol_header.protocol_id
        == messages::ProtocolMessageHeader::PROTOCOL_ID_SECURE_CHANNEL
        && message.protocol_header.opcode == messages::ProtocolMessageHeader::OPCODE_ACK
    {
        log::trace!(
            "standalone ack exchange:{} ack_counter:{}",
            message.protocol_header.exchange_id,
            message.protocol_header.ack_counter
        );
        return Ok(());
    }

    // 7. Route by exchange ID
    let exchange_id = message.protocol_header.exchange_id;
    let sender = {
        let mut pending = pending_exchanges.lock().unwrap();
        pending.remove(&exchange_id)
    };

    match sender {
        Some(tx) => {
            // Response to a pending request
            let _ = tx.send(message);
        }
        None => {
            // Unsolicited event
            let _ = event_tx.send(message).await;
        }
    }

    Ok(())
}

async fn send_ack(
    session: &Arc<Session>,
    transport_conn: &Arc<transport::Connection>,
    message: &Message,
) -> Result<()> {
    let ack = messages::ack(
        message.protocol_header.exchange_id,
        message.message_header.message_counter as i64,
    )?;
    let out = session.encode_message(&ack)?;
    transport_conn.send(&out).await?;
    log::trace!(
        "sending ack for exchange:{} counter:{}",
        message.protocol_header.exchange_id,
        message.message_header.message_counter
    );
    Ok(())
}

async fn check_retransmit(
    transport_conn: &Arc<transport::Connection>,
    unacked: &Arc<Mutex<HashMap<u32, UnackedMessage>>>,
    pending_exchanges: &Arc<std::sync::Mutex<HashMap<u16, oneshot::Sender<Message>>>>,
) {
    let mut to_retransmit = Vec::new();
    {
        let mut unacked_lock = unacked.lock().await;
        let mut to_remove = Vec::new();

        for (counter, msg) in unacked_lock.iter_mut() {
            let age = msg.original_time.elapsed();
            let since_last_send = msg.last_sent.elapsed();
            log::trace!("counter {} age:{:?} since_last:{:?}", counter, age, since_last_send);

            if age >= MAX_RETRANSMIT_AGE {
                log::debug!("giving up on counter {} after {:?}", counter, age);
                // Signal failure to waiting request by removing sender (closes channel)
                if let Some(exch) = msg.exchange_id {
                    pending_exchanges.lock().unwrap().remove(&exch);
                }
                to_remove.push(*counter);
            } else if since_last_send >= RETRANSMIT_THRESHOLD {
                log::trace!("retransmit counter = {} exchange = {}", counter, msg.exchange_id.unwrap_or(0));
                to_retransmit.push(msg.data.clone());
                //if let Err(e) = transport_conn.send(&msg.data).await {
                //    log::debug!("retransmit failed: {:?}", e);
                //}
                msg.last_sent = Instant::now();  // Reset for next retransmit
            }
        }
        for counter in to_remove {
            unacked_lock.remove(&counter);
        }
    }
    // Send outside of lock
    for data in to_retransmit {
        if let Err(e) = transport_conn.send(&data).await {
            log::debug!("retransmit failed: {:?}", e);
        }
    }
}