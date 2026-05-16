use anyhow::Result;
use std::{collections::HashMap, time::Duration};

use crate::{messages, session, transport::ConnectionTrait};

const RECEIVE_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_RETRANSMIT_TIME: Duration = Duration::from_secs(10);
const RELIABLE_MAX_WAIT_TIME: Duration = Duration::from_secs(60);

pub struct RetrContext<'a> {
    /// ids of already received messages to detect duplicates
    received: HashMap<u32, bool>,
    /// sent messages not yet acknowledged, keyed by message_counter, value is (exchange_id, bytes)
    sent: HashMap<u32, (u16, Vec<u8>)>,
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
            received: HashMap::new(),
            sent: HashMap::new(),
            subscribed_exchanges: HashMap::new(),
            connection,
            session,
        }
    }
    fn send_internal(&mut self, d: &[u8], exchange_id: u16) {
        let reliable = self.connection.is_reliable();
        if !reliable {
            let h = messages::MessageHeader::decode(d).unwrap();
            log::trace!("send msg counter:{}", h.0.message_counter);
            self.sent.insert(h.0.message_counter, (exchange_id, d.to_owned()));
        }
    }
    fn received_ack(&mut self, c: u32) {
        log::trace!("received ack counter:{}", c);
        self.sent.remove(&c);
    }

    fn implicit_ack_exchange(&mut self, exchange_id: u16) {
        self.sent.retain(|_, (eid, _)| *eid != exchange_id);
    }
    fn received(&mut self, c: u32) -> bool {
        if let std::collections::hash_map::Entry::Vacant(e) = self.received.entry(c) {
            e.insert(true);
            true
        } else {
            false
        }
    }
    fn to_resend(&self) -> Option<Vec<u8>> {
        if let Some((cnt, (_eid, msg))) = self.sent.iter().next() {
            log::trace!("retransmit counter = {}", cnt);
            Some(msg.clone())
        } else {
            None
        }
    }

    pub fn subscribe_exchange(&mut self, e: u16) {
        self.subscribed_exchanges.insert(e, true);
    }
    pub async fn get_next_message(&mut self) -> Result<messages::Message> {
        let reliable = self.connection.is_reliable();
        if reliable {
            loop {
                let resp = self.connection.receive(RELIABLE_MAX_WAIT_TIME).await?;
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
        let start_time = tokio::time::Instant::now();
        loop {
            if start_time.elapsed() > MAX_RETRANSMIT_TIME {
                anyhow::bail!("retransmit timeout exceeded");
            }
            // try to receive
            let resp = self.connection.receive(RECEIVE_TIMEOUT).await;
            let resp = match resp {
                Ok(v) => v,
                Err(e) => {
                    if e.downcast_ref::<crate::transport::ConnectionClosed>().is_some() {
                        return Err(e);
                    }
                    if let Some(r) = self.to_resend() {
                        self.connection.send(&r).await?;
                    }
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

            // duplicit check says we already did see this message
            if !self.received(decoded.message_header.message_counter) {
                // only thing to do is to send ack - lost ack may be reason to see duplicit message
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
