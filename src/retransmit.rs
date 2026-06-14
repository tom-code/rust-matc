//! MRP (Matter spec 4.12) reliable delivery for handshake exchanges.
//!
//! [`RetrContext`] wraps a session + transport connection and retransmits
//! unacknowledged messages with exponential backoff and jitter derived from
//! the peer's advertised intervals ([`ConnectionTrait::mrp_params`], SAI when
//! the peer is active within SAT, SII otherwise). A message is given up on
//! after [`mrp::MRP_MAX_TRANSMISSIONS`] transmissions; waiting for a response
//! is additionally bounded by an overall deadline.

use anyhow::Result;
use std::{collections::HashMap, time::Duration};
use tokio::time::Instant;

use crate::{messages, mrp, session, transport::ConnectionTrait};

const MAX_RESPONSE_WAIT: Duration = Duration::from_secs(60);

struct SentEntry {
    exchange_id: u16,
    data: Vec<u8>,
    transmissions: u32,
    next_retransmit: Instant,
}

pub struct RetrContext<'a> {
    /// sent messages not yet acknowledged, keyed by message_counter
    sent: HashMap<u32, SentEntry>,
    /// exchange-ids use is interested in. empty for all
    subscribed_exchanges: HashMap<u16, bool>,
    connection: &'a dyn ConnectionTrait,
    session: &'a session::Session,
}

impl<'b> RetrContext<'b> {
    pub fn new<'a: 'b>(
        connection: &'a dyn ConnectionTrait,
        session: &'a session::Session,
    ) -> Self {
        Self {
            sent: HashMap::new(),
            subscribed_exchanges: HashMap::new(),
            connection,
            session,
        }
    }
    fn backoff_from_now(&self, retransmission_index: u32) -> Instant {
        let base = mrp::base_interval(
            &self.connection.mrp_params(),
            self.connection.last_received_elapsed(),
        );
        Instant::now() + mrp::backoff_interval(base, retransmission_index)
    }
    fn send_internal(&mut self, d: &[u8], exchange_id: u16) {
        let reliable = self.connection.is_reliable();
        if !reliable {
            let h = messages::MessageHeader::decode(d).unwrap();
            log::trace!("send msg counter:{}", h.0.message_counter);
            self.sent.insert(
                h.0.message_counter,
                SentEntry {
                    exchange_id,
                    data: d.to_owned(),
                    transmissions: 1,
                    next_retransmit: self.backoff_from_now(0),
                },
            );
        }
    }
    fn received_ack(&mut self, c: u32) {
        log::trace!("received ack counter:{}", c);
        self.sent.remove(&c);
    }

    fn implicit_ack_exchange(&mut self, exchange_id: u16) {
        self.sent.retain(|_, e| e.exchange_id != exchange_id);
    }

    async fn retransmit_due(&mut self) -> Result<()> {
        let now = Instant::now();
        let due: Vec<u32> = self
            .sent
            .iter()
            .filter(|(_, e)| e.next_retransmit <= now)
            .map(|(c, _)| *c)
            .collect();
        for counter in due {
            let entry = self.sent.get(&counter).unwrap();
            if entry.transmissions >= mrp::MRP_MAX_TRANSMISSIONS {
                anyhow::bail!(
                    "MRP retransmit limit reached for counter {} after {} transmissions",
                    counter,
                    entry.transmissions
                );
            }
            let data = entry.data.clone();
            log::trace!(
                "retransmit counter = {} attempt {}",
                counter,
                entry.transmissions + 1
            );
            self.connection.send(&data).await?;
            let next = self.backoff_from_now(entry.transmissions);
            let entry = self.sent.get_mut(&counter).unwrap();
            entry.transmissions += 1;
            entry.next_retransmit = next;
        }
        Ok(())
    }

    pub fn subscribe_exchange(&mut self, e: u16) {
        self.subscribed_exchanges.insert(e, true);
    }
    pub async fn get_next_message(&mut self) -> Result<messages::Message> {
        let reliable = self.connection.is_reliable();
        if reliable {
            loop {
                let resp = self.connection.receive(MAX_RESPONSE_WAIT).await?;
                let resp = match self.session.decode_message(&resp) {
                    Ok(resp) => resp,
                    Err(e) => {
                        log::debug!("can't decode incoming message {:?}", e);
                        return Err(anyhow::anyhow!("failed to receive initial message in reliable exchange: {:?}", e));
                    }
                };
                let decoded = messages::Message::decode(&resp)?;
                if decoded.protocol_header.protocol_id
                    == messages::ProtocolMessageHeader::PROTOCOL_ID_SECURE_CHANNEL
                    && decoded.protocol_header.opcode == messages::ProtocolMessageHeader::OPCODE_ACK
                {
                    log::trace!("reliable transport: skipping standalone ack");
                    continue;
                }
                return Ok(decoded);
            }
        }
        // For peers advertising intervals near the spec cap the overall deadline
        // can fire before all MRP transmissions are spent; acceptable bound.
        let deadline = Instant::now() + MAX_RESPONSE_WAIT;
        loop {
            let now = Instant::now();
            if now >= deadline {
                anyhow::bail!("response timeout");
            }
            let timeout = self
                .sent
                .values()
                .map(|e| e.next_retransmit)
                .min()
                .unwrap_or(deadline)
                .min(deadline)
                .saturating_duration_since(now);
            let resp = self.connection.receive(timeout).await;
            let resp = match resp {
                Ok(v) => v,
                Err(e) => {
                    if e.downcast_ref::<crate::transport::ConnectionClosed>().is_some() {
                        return Err(e);
                    }
                    self.retransmit_due().await?;
                    continue;
                }
            };
            let resp = match self.session.decode_message(&resp) {
                Ok(resp) => resp,
                Err(e) => {
                    log::debug!("can't decode incoming message {:?}", e);
                    continue;
                }
            };
            let decoded = messages::Message::decode(&resp)?;
            log::trace!("received message {:?}", decoded);

            // apply ack - remove from retransmit buffer
            self.received_ack(decoded.protocol_header.ack_counter);

            self.implicit_ack_exchange(decoded.protocol_header.exchange_id);

            if !self.session.counter_is_new(decoded.message_header.message_counter) {
                // lost ack may be reason to see duplicit message
                if decoded.protocol_header.exchange_flags
                    & messages::ProtocolMessageHeader::FLAG_RELIABILITY
                    != 0
                {
                    let ack = messages::ack(
                        decoded.protocol_header.exchange_id,
                        decoded.message_header.message_counter as i64,
                    )?;
                    let out = self.session.encode_message(&ack)?;
                    self.connection.send(&out).await?;
                    log::trace!(
                        "sending ack for exchange:{} counter:{}",
                        decoded.protocol_header.exchange_id,
                        decoded.message_header.message_counter
                    );
                }
                log::trace!(
                    "dropping duplicit message exchange:{} counter:{}",
                    decoded.protocol_header.exchange_id,
                    decoded.message_header.message_counter
                );
                continue;
            }
            if decoded.protocol_header.protocol_id
                == messages::ProtocolMessageHeader::PROTOCOL_ID_SECURE_CHANNEL
                && decoded.protocol_header.opcode == messages::ProtocolMessageHeader::OPCODE_ACK
            {
                log::trace!(
                    "standalone ack exchange:{} ack_counter:{}",
                    decoded.protocol_header.exchange_id,
                    decoded.protocol_header.ack_counter
                );
                continue;
            }

            if decoded.protocol_header.exchange_flags
                & messages::ProtocolMessageHeader::FLAG_RELIABILITY
                != 0
            {
                let ack = messages::ack(
                    decoded.protocol_header.exchange_id,
                    decoded.message_header.message_counter as i64,
                )?;
                let out = self.session.encode_message(&ack)?;
                self.connection.send(&out).await?;
                log::trace!(
                    "sending ack for exchange:{} counter:{}",
                    decoded.protocol_header.exchange_id,
                    decoded.message_header.message_counter
                );
            }

            if !self.subscribed_exchanges.is_empty()
                && !self
                    .subscribed_exchanges
                    .contains_key(&decoded.protocol_header.exchange_id)
            {
                continue;
            }
            return Ok(decoded);
        }
    }
    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        // `data` is the protocol-layer message (protocol header + payload);
        // session.encode_message prepends the MessageHeader.
        let (ph, _) = messages::ProtocolMessageHeader::decode(data)?;
        let out = self.session.encode_message(data)?;
        self.send_internal(&out, ph.exchange_id);
        self.connection.send(&out).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestConn {
        sent: std::sync::Mutex<Vec<(Instant, Vec<u8>)>>,
    }

    #[async_trait::async_trait]
    impl ConnectionTrait for TestConn {
        async fn send(&self, data: &[u8]) -> Result<()> {
            self.sent.lock().unwrap().push((Instant::now(), data.to_vec()));
            Ok(())
        }
        async fn receive(&self, timeout: Duration) -> Result<Vec<u8>> {
            tokio::time::sleep(timeout).await;
            anyhow::bail!("timeout")
        }
    }

    #[tokio::test(start_paused = true)]
    async fn test_retransmit_give_up() {
        let conn = TestConn { sent: std::sync::Mutex::new(Vec::new()) };
        let session = session::Session::new();
        let mut ctx = RetrContext::new(&conn, &session);
        ctx.send(&messages::ack(1, 2).unwrap()).await.unwrap();

        let err = ctx.get_next_message().await.unwrap_err();
        assert!(err.to_string().contains("MRP retransmit limit"), "got: {}", err);

        let sent = conn.sent.lock().unwrap();
        assert_eq!(sent.len(), mrp::MRP_MAX_TRANSMISSIONS as usize);
        // gap n follows backoff with the default 500ms idle interval
        for (n, w) in sent.windows(2).enumerate() {
            let gap = (w[1].0 - w[0].0).as_secs_f64();
            let lower = 0.5 * mrp::MRP_BACKOFF_MARGIN
                * mrp::MRP_BACKOFF_BASE.powi(n.saturating_sub(1) as i32);
            let upper = lower * (1.0 + mrp::MRP_BACKOFF_JITTER);
            assert!(
                gap >= lower - 1e-6 && gap <= upper + 1e-3,
                "gap {} = {} not in [{}, {}]",
                n, gap, lower, upper
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn test_response_wait_timeout() {
        let conn = TestConn { sent: std::sync::Mutex::new(Vec::new()) };
        let session = session::Session::new();
        let mut ctx = RetrContext::new(&conn, &session);

        let start = Instant::now();
        let err = ctx.get_next_message().await.unwrap_err();
        assert!(err.to_string().contains("response timeout"), "got: {}", err);
        assert!(start.elapsed() >= MAX_RESPONSE_WAIT);
        assert!(conn.sent.lock().unwrap().is_empty());
    }
}
