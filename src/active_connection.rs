use anyhow::{Context, Result};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::{messages::{self, Message, ProtocolMessageHeader}, session::Session, transport::ConnectionTrait};

const RECEIVE_TIMEOUT: Duration = Duration::from_secs(1);
const RETRANSMIT_THRESHOLD: Duration = Duration::from_secs(3);
const MAX_RETRANSMIT_AGE: Duration = Duration::from_secs(10);
const MAX_CACHED_COUNTERS: usize = 512;

struct UnackedMessage {
    data: Vec<u8>,
    original_time: Instant,
    last_sent: Instant,
    exchange_id: Option<u16>,
}

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

    fn insert(&mut self, counter: u32) -> bool {
        if !self.set.insert(counter) {
            return false;
        }
        self.order.push_back(counter);
        while self.order.len() > self.max_size {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }
        true
    }
}

struct ReadLoopState {
    // Child of the permanent cancel token; firing this stops the current loop iteration.
    pause: CancellationToken,
    handle: JoinHandle<()>,
}

/// Active connection with background read task for continuous message handling.
pub struct ActiveConnection {
    pub(crate) transport_conn: Arc<dyn ConnectionTrait>,
    // Stores the current session Arc; updated atomically on reauth.
    session_holder: std::sync::Mutex<Arc<Session>>,

    pending_exchanges: Arc<std::sync::Mutex<HashMap<u16, oneshot::Sender<Message>>>>,
    unacked: Arc<Mutex<HashMap<u32, UnackedMessage>>>,

    event_tx: mpsc::Sender<Message>,
    event_rx: Mutex<mpsc::Receiver<Message>>,

    // Fired by Drop to permanently shut down the read loop.
    cancel: CancellationToken,
    // Current read loop task; replaced on each reauth.
    read_loop_state: Mutex<Option<ReadLoopState>>,
}

impl ActiveConnection {
    /// Create from transport connection and authenticated session.
    /// Spawns a background task that continuously reads from the connection.
    pub fn new(conn: Arc<dyn ConnectionTrait>, session: Session) -> Self {
        let (event_tx, event_rx) = mpsc::channel(32);
        let cancel = CancellationToken::new();
        let session_arc = Arc::new(session);
        let session_holder = std::sync::Mutex::new(session_arc.clone());
        let pending_exchanges = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let unacked = Arc::new(Mutex::new(HashMap::new()));
        let received_counters = Arc::new(std::sync::Mutex::new(ReceivedCounters::new(MAX_CACHED_COUNTERS)));

        // The read loop is cancelled by either this pause token or the parent cancel token.
        let pause = cancel.child_token();
        let handle = tokio::spawn(connection_read_loop(
            conn.clone(),
            session_arc,
            pending_exchanges.clone(),
            unacked.clone(),
            received_counters,
            event_tx.clone(),
            pause.clone(),
        ));

        Self {
            transport_conn: conn,
            session_holder,
            pending_exchanges,
            unacked,
            event_tx,
            event_rx: Mutex::new(event_rx),
            cancel,
            read_loop_state: Mutex::new(Some(ReadLoopState { pause, handle })),
        }
    }

    pub(crate) async fn pause_read_loop(&self) {
        let old_state = {
            let mut state = self.read_loop_state.lock().await;
            state.take()
        };
        if let Some(s) = old_state {
            s.pause.cancel();
            let _ = s.handle.await;
        }
    }

    pub async fn reauth_with_session(&self, new_session: Session) -> Result<()> {
        // Stop the current read loop and wait for it to exit (no-op if already paused).
        self.pause_read_loop().await;

        // Discard any pending exchanges from the old session.
        self.pending_exchanges.lock().unwrap().clear();
        self.unacked.lock().await.clear();

        // Install the new session.
        *self.session_holder.lock().unwrap() = Arc::new(new_session);
        let new_session_arc = self.session_holder.lock().unwrap().clone();

        // Spawn a fresh read loop on the same transport connection.
        let new_pause = self.cancel.child_token();
        let new_received_counters = Arc::new(std::sync::Mutex::new(ReceivedCounters::new(MAX_CACHED_COUNTERS)));
        let handle = tokio::spawn(connection_read_loop(
            self.transport_conn.clone(),
            new_session_arc,
            self.pending_exchanges.clone(),
            self.unacked.clone(),
            new_received_counters,
            self.event_tx.clone(),
            new_pause.clone(),
        ));

        *self.read_loop_state.lock().await = Some(ReadLoopState { pause: new_pause, handle });
        Ok(())
    }

    async fn send_internal(&self, exchange_id: u16, data: &[u8]) -> Result<()> {
        let session = self.session_holder.lock().unwrap().clone();
        let encoded = session.encode_message(data)?;
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

    pub async fn request(&self, exchange_id: u16, data: &[u8]) -> Result<Message> {
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.pending_exchanges.lock().unwrap();
            pending.insert(exchange_id, tx);
        }

        if let Err(e) = self.send_internal(exchange_id, data).await {
            log::debug!("error sending request on exchange {}: {:?}; cleanup retransmit/exchange maps", exchange_id, e);
            let mut pending = self.pending_exchanges.lock().unwrap();
            pending.remove(&exchange_id);
            return Err(e);
        }

        rx.await.context("channel closed while waiting for response")
    }

    pub async fn send(&self, data: &[u8]) -> Result<()> {
        let session = self.session_holder.lock().unwrap().clone();
        let encoded = session.encode_message(data)?;
        self.track_sent(&encoded, None).await;
        self.transport_conn.send(&encoded).await?;
        Ok(())
    }

    pub async fn recv_event(&self) -> Option<Message> {
        let mut rx = self.event_rx.lock().await;
        rx.recv().await
    }

    pub fn try_recv_event(&self) -> Option<Message> {
        match self.event_rx.try_lock() {
            Ok(mut rx) => rx.try_recv().ok(),
            Err(_) => None,
        }
    }

    async fn track_sent(&self, encoded: &[u8], exchange_id: Option<u16>) {
        if self.transport_conn.is_reliable() {
            return;
        }
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
        // Cancels the parent token which also cancels any active child (read loop pause) token.
        self.cancel.cancel();
    }
}

async fn connection_read_loop(
    transport_conn: Arc<dyn ConnectionTrait>,
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
                        if !transport_conn.is_reliable() {
                            check_retransmit(&transport_conn, &unacked, &pending_exchanges).await;
                        }
                    }
                }
            }
        }
    }
}

async fn process_incoming(
    data: &[u8],
    session: &Arc<Session>,
    transport_conn: &Arc<dyn ConnectionTrait>,
    pending_exchanges: &Arc<std::sync::Mutex<HashMap<u16, oneshot::Sender<Message>>>>,
    unacked: &Arc<Mutex<HashMap<u32, UnackedMessage>>>,
    received_counters: &Arc<std::sync::Mutex<ReceivedCounters>>,
    event_tx: &mpsc::Sender<Message>,
) -> Result<()> {
    log::trace!("received raw data: {:x?}", data);
    let decoded_data = session.decode_message(data);
    let decoded_data = match decoded_data {
        Ok(d) => d,
        Err(e) => {
            log::debug!("failed to decode incoming message: {}", e);
            return Ok(());
        }
    };

    let message = Message::decode(&decoded_data)?;
    log::trace!("received message {:?}", message);

    if message.protocol_header.exchange_flags & ProtocolMessageHeader::FLAG_ACK != 0 {
        let mut unacked_lock = unacked.lock().await;
        unacked_lock.remove(&message.protocol_header.ack_counter);
        log::trace!(
            "received ack for counter:{}",
            message.protocol_header.ack_counter
        );
    }

    let is_new = {
        let mut received = received_counters.lock().unwrap();
        received.insert(message.message_header.message_counter)
    };

    if !is_new {
        send_ack(session, transport_conn, &message).await?;
        log::trace!(
            "dropping duplicate message exchange:{} counter:{}",
            message.protocol_header.exchange_id,
            message.message_header.message_counter
        );
        return Ok(());
    }

    if message.protocol_header.exchange_flags & ProtocolMessageHeader::FLAG_RELIABILITY != 0 {
        send_ack(session, transport_conn, &message).await?;
    }

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

    let exchange_id = message.protocol_header.exchange_id;
    let sender = {
        let mut pending = pending_exchanges.lock().unwrap();
        pending.remove(&exchange_id)
    };

    match sender {
        Some(tx) => {
            let _ = tx.send(message);
        }
        None => {
            let _ = event_tx.send(message).await;
        }
    }

    Ok(())
}

async fn send_ack(
    session: &Arc<Session>,
    transport_conn: &Arc<dyn ConnectionTrait>,
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
    transport_conn: &Arc<dyn ConnectionTrait>,
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
                if let Some(exch) = msg.exchange_id {
                    pending_exchanges.lock().unwrap().remove(&exch);
                }
                to_remove.push(*counter);
            } else if since_last_send >= RETRANSMIT_THRESHOLD {
                log::trace!("retransmit counter = {} exchange = {}", counter, msg.exchange_id.unwrap_or(0));
                to_retransmit.push(msg.data.clone());
                msg.last_sent = Instant::now();
            }
        }
        for counter in to_remove {
            unacked_lock.remove(&counter);
        }
    }
    for data in to_retransmit {
        if let Err(e) = transport_conn.send(&data).await {
            log::debug!("retransmit failed: {:?}", e);
        }
    }
}
