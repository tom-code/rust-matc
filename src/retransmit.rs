use anyhow::Result;
use std::{collections::HashMap, time::Duration};

use crate::{messages, session, transport};

pub struct RetrContext<'a> {
    /// ids of already received messages to detect duplicates
    received: HashMap<u32, bool>,
    /// sent messages not yet acknowledged
    sent: HashMap<u32, Vec<u8>>,
    /// exchange-ids use is interested in. empty for all
    subscribed_exchanges: HashMap<u16, bool>,
    connection: &'a transport::Connection,
    session: &'a mut session::Session,
}

impl<'b> RetrContext<'b> {
    pub fn new<'a: 'b>(
        connection: &'a transport::Connection,
        session: &'a mut session::Session,
    ) -> Self {
        Self {
            received: HashMap::new(),
            sent: HashMap::new(),
            subscribed_exchanges: HashMap::new(),
            connection,
            session,
        }
    }
    fn send_internal(&mut self, d: &[u8]) {
        let h = messages::MessageHeader::decode(d).unwrap();
        log::trace!("send msg counter:{}", h.0.message_counter);
        self.sent.insert(h.0.message_counter, d.to_owned());
    }
    fn received_ack(&mut self, c: u32) {
        log::trace!("received ack counter:{}", c);
        self.sent.remove(&c);
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
        //self.sent.iter().next().map(|v| v.1.clone())
        if let Some((cnt, msg)) = self.sent.iter().next() {
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
        loop {
            // try to receive
            let resp = self.connection.receive(Duration::from_secs(3)).await;
            let resp = match resp {
                Ok(v) => v,
                Err(_) => {
                    // if receive failed and there is something to retransmit then retransmit
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
        let out = self.session.encode_message(data)?;
        self.send_internal(&out);
        self.connection.send(&out).await?;
        Ok(())
    }
}
