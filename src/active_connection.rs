use anyhow::{Context, Result};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::{im, messages::{self, Message, ProtocolMessageHeader}, session::Session, transport::ConnectionTrait};

const RECEIVE_TIMEOUT: Duration = Duration::from_secs(1);
const EXCHANGE_CHANNEL_CAPACITY: usize = 8;
const SUBSCRIPTION_CHANNEL_CAPACITY: usize = 16;
const RETRANSMIT_THRESHOLD: Duration = Duration::from_secs(3);
const MAX_RETRANSMIT_AGE: Duration = Duration::from_secs(10);
const PARTIAL_REPORT_MAX_AGE: Duration = Duration::from_secs(60);

struct UnackedMessage {
    data: Vec<u8>,
    original_time: Instant,
    last_sent: Instant,
    exchange_id: Option<u16>,
}

struct ReadLoopState {
    // Child of the permanent cancel token; firing this stops the current loop iteration.
    pause: CancellationToken,
    handle: JoinHandle<()>,
}

// Shared state handed to the background read loop task.
struct ReadLoopCtx {
    transport_conn: Arc<dyn ConnectionTrait>,
    session: Arc<Session>,
    pending_exchanges: Arc<std::sync::Mutex<HashMap<u16, mpsc::Sender<Message>>>>,
    unacked: Arc<Mutex<HashMap<u32, UnackedMessage>>>,
    event_tx: mpsc::Sender<Message>,
    subscriptions: Arc<std::sync::Mutex<HashMap<u32, mpsc::Sender<im::ReportUpdate>>>>,
    auto_status_response: Arc<AtomicBool>,
}

// Reassembly state for a chunked unsolicited (device-initiated) ReportData,
// keyed by the device's exchange id. Owned locally by the read loop.
struct PartialReport {
    merged: im::ReportData,
    raw: Vec<Message>,
    started: Instant,
}

/// Active connection with background read task for continuous message handling.
pub struct ActiveConnection {
    pub(crate) transport_conn: Arc<dyn ConnectionTrait>,
    // Stores the current session Arc; updated atomically on reauth.
    session_holder: std::sync::Mutex<Arc<Session>>,

    pending_exchanges: Arc<std::sync::Mutex<HashMap<u16, mpsc::Sender<Message>>>>,
    unacked: Arc<Mutex<HashMap<u32, UnackedMessage>>>,

    event_tx: mpsc::Sender<Message>,
    event_rx: Mutex<mpsc::Receiver<Message>>,

    // Decoded subscription updates routed by subscription id.
    subscriptions: Arc<std::sync::Mutex<HashMap<u32, mpsc::Sender<im::ReportUpdate>>>>,
    // When set, the read loop replies to unsolicited ReportData with an IM StatusResponse.
    auto_status_response: Arc<AtomicBool>,

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
        let subscriptions = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let auto_status_response = Arc::new(AtomicBool::new(true));

        // The read loop is cancelled by either this pause token or the parent cancel token.
        let pause = cancel.child_token();
        let handle = tokio::spawn(connection_read_loop(
            ReadLoopCtx {
                transport_conn: conn.clone(),
                session: session_arc,
                pending_exchanges: pending_exchanges.clone(),
                unacked: unacked.clone(),
                event_tx: event_tx.clone(),
                subscriptions: subscriptions.clone(),
                auto_status_response: auto_status_response.clone(),
            },
            pause.clone(),
        ));

        Self {
            transport_conn: conn,
            session_holder,
            pending_exchanges,
            unacked,
            event_tx,
            event_rx: Mutex::new(event_rx),
            subscriptions,
            auto_status_response,
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
        // Subscriptions do not survive a new session; closing the channels
        // makes Subscription::next() return None.
        self.subscriptions.lock().unwrap().clear();

        // Install the new session.
        *self.session_holder.lock().unwrap() = Arc::new(new_session);
        let new_session_arc = self.session_holder.lock().unwrap().clone();

        // Spawn a fresh read loop on the same transport connection.
        // The new session carries fresh message reception state.
        let new_pause = self.cancel.child_token();
        let handle = tokio::spawn(connection_read_loop(
            ReadLoopCtx {
                transport_conn: self.transport_conn.clone(),
                session: new_session_arc,
                pending_exchanges: self.pending_exchanges.clone(),
                unacked: self.unacked.clone(),
                event_tx: self.event_tx.clone(),
                subscriptions: self.subscriptions.clone(),
                auto_status_response: self.auto_status_response.clone(),
            },
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

    /// Open a logical exchange: messages received for this exchange id are
    /// routed to the returned handle until it is dropped. Allows multi-message
    /// transactions (chunked reports, subscribe priming + response).
    pub(crate) fn open_exchange(&self, exchange_id: u16) -> Exchange<'_> {
        let (tx, rx) = mpsc::channel(EXCHANGE_CHANNEL_CAPACITY);
        self.pending_exchanges.lock().unwrap().insert(exchange_id, tx);
        Exchange { conn: self, id: exchange_id, rx }
    }

    pub async fn request(&self, exchange_id: u16, data: &[u8]) -> Result<Message> {
        let mut exchange = self.open_exchange(exchange_id);
        exchange.send(data).await?;
        exchange.recv().await
    }

    /// Register a subscription id; decoded updates for it are delivered to the
    /// returned receiver instead of the raw event channel.
    pub(crate) fn register_subscription(&self, id: u32) -> mpsc::Receiver<im::ReportUpdate> {
        let (tx, rx) = mpsc::channel(SUBSCRIPTION_CHANNEL_CAPACITY);
        self.subscriptions.lock().unwrap().insert(id, tx);
        rx
    }

    pub(crate) fn subscriptions_handle(
        &self,
    ) -> Arc<std::sync::Mutex<HashMap<u32, mpsc::Sender<im::ReportUpdate>>>> {
        self.subscriptions.clone()
    }

    /// Enable or disable automatic IM StatusResponse replies to unsolicited
    /// ReportData (enabled by default).
    pub fn set_auto_status_response(&self, enabled: bool) {
        self.auto_status_response.store(enabled, Ordering::Relaxed);
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

/// Handle for a multi-message exchange. Incoming messages for the exchange id
/// are delivered to [Exchange::recv] until the handle is dropped.
pub(crate) struct Exchange<'a> {
    conn: &'a ActiveConnection,
    pub(crate) id: u16,
    rx: mpsc::Receiver<Message>,
}

impl Exchange<'_> {
    pub(crate) async fn send(&self, data: &[u8]) -> Result<()> {
        self.conn.send_internal(self.id, data).await
    }

    pub(crate) async fn recv(&mut self) -> Result<Message> {
        self.rx
            .recv()
            .await
            .context("channel closed while waiting for response")
    }
}

impl Drop for Exchange<'_> {
    fn drop(&mut self) {
        self.conn.pending_exchanges.lock().unwrap().remove(&self.id);
    }
}

async fn connection_read_loop(ctx: ReadLoopCtx, cancel: CancellationToken) {
    let mut partial_reports: HashMap<u16, PartialReport> = HashMap::new();
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,

            result = ctx.transport_conn.receive(RECEIVE_TIMEOUT) => {
                match result {
                    Ok(data) => {
                        log::trace!("received {} bytes", data.len());
                        if let Err(e) = process_incoming(&data, &ctx, &mut partial_reports).await {
                            log::debug!("error processing incoming message: {:?}", e);
                        }
                    }
                    Err(_) => {
                        if !ctx.transport_conn.is_reliable() {
                            check_retransmit(&ctx.transport_conn, &ctx.unacked, &ctx.pending_exchanges).await;
                        }
                        partial_reports.retain(|exchange, partial| {
                            let keep = partial.started.elapsed() < PARTIAL_REPORT_MAX_AGE;
                            if !keep {
                                log::debug!("discarding stale partial report on exchange {}", exchange);
                            }
                            keep
                        });
                    }
                }
            }
        }
    }
}

async fn process_incoming(
    data: &[u8],
    ctx: &ReadLoopCtx,
    partial_reports: &mut HashMap<u16, PartialReport>,
) -> Result<()> {
    log::trace!("received raw data: {:x?}", data);
    let decoded_data = ctx.session.decode_message(data);
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
        let mut unacked_lock = ctx.unacked.lock().await;
        unacked_lock.remove(&message.protocol_header.ack_counter);
        log::trace!(
            "received ack for counter:{}",
            message.protocol_header.ack_counter
        );
    }

    if !ctx.session.counter_is_new(message.message_header.message_counter) {
        if message.protocol_header.exchange_flags & ProtocolMessageHeader::FLAG_RELIABILITY != 0 {
            send_ack(&ctx.session, &ctx.transport_conn, &message).await?;
        }
        log::trace!(
            "dropping duplicate message exchange:{} counter:{}",
            message.protocol_header.exchange_id,
            message.message_header.message_counter
        );
        return Ok(());
    }

    if message.protocol_header.exchange_flags & ProtocolMessageHeader::FLAG_RELIABILITY != 0 {
        send_ack(&ctx.session, &ctx.transport_conn, &message).await?;
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
    // Only messages on exchanges we initiated may match a pending exchange;
    // a device-initiated exchange can reuse the same id without conflict.
    let from_initiator =
        message.protocol_header.exchange_flags & ProtocolMessageHeader::FLAG_INITIATOR != 0;
    let sender = if from_initiator {
        None
    } else {
        ctx.pending_exchanges.lock().unwrap().get(&exchange_id).cloned()
    };

    if let Some(tx) = sender {
        if let Err(e) = tx.try_send(message) {
            log::debug!("dropping message for exchange {}: {}", exchange_id, e);
        }
        return Ok(());
    }

    if message.protocol_header.protocol_id == ProtocolMessageHeader::PROTOCOL_ID_INTERACTION
        && message.protocol_header.opcode == ProtocolMessageHeader::INTERACTION_OPCODE_REPORT_DATA
    {
        return handle_unsolicited_report(ctx, partial_reports, message).await;
    }

    if ctx.event_tx.try_send(message).is_err() {
        log::debug!("event channel full or closed, dropping message for exchange {}", exchange_id);
    }

    Ok(())
}

// Handles a (typically subscription) ReportData on an exchange with no pending
// requester: acks it at the IM level, reassembles chunks, and delivers the
// decoded update to the registered subscription channel.
async fn handle_unsolicited_report(
    ctx: &ReadLoopCtx,
    partial_reports: &mut HashMap<u16, PartialReport>,
    message: Message,
) -> Result<()> {
    let exchange_id = message.protocol_header.exchange_id;

    let report = match im::ReportData::parse(&message.tlv) {
        Ok(r) => r,
        Err(e) => {
            log::debug!("unparseable report data on exchange {}: {}", exchange_id, e);
            if ctx.event_tx.try_send(message).is_err() {
                log::debug!("event channel full or closed, dropping report on exchange {}", exchange_id);
            }
            return Ok(());
        }
    };

    if ctx.auto_status_response.load(Ordering::Relaxed) && !report.suppress_response {
        let flags = messages::im_status_flags_for(message.protocol_header.exchange_flags);
        let resp = messages::im_status_response(
            exchange_id,
            flags,
            message.message_header.message_counter,
        )?;
        let encoded = ctx.session.encode_message(&resp)?;
        if !ctx.transport_conn.is_reliable() {
            if let Ok((header, _)) = messages::MessageHeader::decode(&encoded) {
                let now = Instant::now();
                ctx.unacked.lock().await.insert(header.message_counter, UnackedMessage {
                    data: encoded.clone(),
                    original_time: now,
                    last_sent: now,
                    exchange_id: None,
                });
            }
        }
        ctx.transport_conn.send(&encoded).await?;
        log::trace!("sent status response for report on exchange {}", exchange_id);
    }

    let more_chunks = report.more_chunks;
    let partial = partial_reports.entry(exchange_id).or_insert_with(|| PartialReport {
        merged: im::ReportData::default(),
        raw: Vec::new(),
        started: Instant::now(),
    });
    partial.merged.merge(report);
    partial.raw.push(message);

    if more_chunks {
        return Ok(());
    }

    let partial = partial_reports.remove(&exchange_id).unwrap();
    let subscription_sender = partial
        .merged
        .subscription_id
        .and_then(|id| ctx.subscriptions.lock().unwrap().get(&id).cloned());

    match (subscription_sender, partial.merged.subscription_id) {
        (Some(tx), Some(id)) => {
            let update = im::ReportUpdate {
                subscription_id: id,
                attribute_reports: partial.merged.attribute_reports,
                event_reports: partial.merged.event_reports,
            };
            if let Err(mpsc::error::TrySendError::Closed(_)) = tx.try_send(update) {
                ctx.subscriptions.lock().unwrap().remove(&id);
                log::debug!("subscription {} receiver dropped, deregistering", id);
            }
        }
        _ => {
            for raw in partial.raw {
                if ctx.event_tx.try_send(raw).is_err() {
                    log::debug!("event channel full or closed, dropping report on exchange {}", exchange_id);
                    break;
                }
            }
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
    pending_exchanges: &Arc<std::sync::Mutex<HashMap<u16, mpsc::Sender<Message>>>>,
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
