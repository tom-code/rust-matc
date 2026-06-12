use aes::cipher::crypto_common;
use byteorder::{LittleEndian, WriteBytesExt};

use crate::{messages, util::cryptoutil};
use anyhow::Result;
use std::io::Write;
use std::sync::atomic::{AtomicU32, Ordering};

/// Message Reception State per Matter spec 4.6.5: sliding-window duplicate
/// and replay detection. Tracks the largest received counter plus a bitmap
/// of the MSG_COUNTER_WINDOW_SIZE counters below it. Counters older than the
/// window are rejected. No-rollover semantics (secure unicast counters never
/// wrap; initial counters are random in [1, 2^28]).
#[derive(Default)]
pub(crate) struct MessageReceptionState {
    max_counter: u32,
    /// Bit i set means counter (max_counter - 1 - i) was received.
    window: u32,
    initialized: bool,
}

impl MessageReceptionState {
    /// Returns true if the counter is new (accepted) and records it;
    /// false if it is a duplicate or older than the window.
    pub(crate) fn counter_is_new(&mut self, counter: u32) -> bool {
        if !self.initialized {
            self.initialized = true;
            self.max_counter = counter;
            self.window = 0;
            return true;
        }
        if counter == self.max_counter {
            return false;
        }
        if counter > self.max_counter {
            let shift = counter - self.max_counter;
            self.window = if shift > 32 {
                0
            } else {
                self.window.checked_shl(shift).unwrap_or(0) | (1 << (shift - 1))
            };
            self.max_counter = counter;
            return true;
        }
        let diff = self.max_counter - counter;
        if diff > 32 {
            return false;
        }
        let bit = 1u32 << (diff - 1);
        if self.window & bit != 0 {
            return false;
        }
        self.window |= bit;
        true
    }
}

pub struct Session {
    pub session_id: u16,
    pub my_session_id: u16,
    counter: AtomicU32,
    reception_state: std::sync::Mutex<MessageReceptionState>,
    pub local_node: Option<Vec<u8>>,
    pub remote_node: Option<Vec<u8>>,
    pub encrypt_key: Option<crypto_common::Key<Aes128Ccm>>,
    pub decrypt_key: Option<crypto_common::Key<Aes128Ccm>>,
    /// Fabric index for this session (0 = PASE / unassigned).
    pub fabric_index: u8,
}
type Aes128Ccm = ccm::Ccm<aes::Aes128, ccm::consts::U16, ccm::consts::U13>;
impl Session {
    pub fn new() -> Self {
        Self {
            session_id: 0,
            my_session_id: 0,
            counter: AtomicU32::new(crate::util::cryptoutil::initial_message_counter()),
            reception_state: std::sync::Mutex::new(MessageReceptionState::default()),
            local_node: Some([0, 0, 0, 0, 0, 0, 0, 0].to_vec()),
            remote_node: None,
            encrypt_key: None,
            decrypt_key: None,
            fabric_index: 0,
        }
    }
    pub fn set_encrypt_key(&mut self, k: &[u8]) {
        self.encrypt_key = Some(*crypto_common::Key::<Aes128Ccm>::from_slice(k))
    }
    pub fn set_decrypt_key(&mut self, k: &[u8]) {
        self.decrypt_key = Some(*crypto_common::Key::<Aes128Ccm>::from_slice(k))
    }

    pub fn encode_message(&self, data: &[u8]) -> Result<Vec<u8>> {
        let counter = self.counter.fetch_add(1, Ordering::Relaxed);
        let mg = messages::MessageHeader {
            flags: 0,
            security_flags: 0,
            session_id: self.session_id,
            message_counter: counter,
            source_node_id: self.local_node.clone(),
            destination_node_id: self.remote_node.clone(),
        };
        let mut b = mg.encode()?;
        match self.encrypt_key {
            Some(key) => {
                let nonce = self.make_nonce3(counter)?;
                let enc = cryptoutil::aes128_ccm_encrypt(&key, &nonce, &b, data)?;
                b.extend_from_slice(&enc);
            }
            None => b.extend_from_slice(data),
        };

        Ok(b)
    }

    pub fn decode_message(&self, data: &[u8]) -> Result<Vec<u8>> {
        if self.decrypt_key.is_none() {
            return Ok(data.to_vec());
        }
        let (header, rest) = messages::MessageHeader::decode(data)?;
        if header.session_id != self.my_session_id {
            anyhow::bail!(
                "session id mismatch. expected:{} got:{}",
                self.my_session_id,
                header.session_id
            );
        }
        log::trace!("decode msg header:{:?} session:{}", header, self.session_id);
        let nonce = Self::make_nonce3_extern(header.message_counter, self.remote_node.as_deref())?;
        let add = &data[..data.len() - rest.len()];
        let decoded = cryptoutil::aes128_ccm_decrypt(
            &self.decrypt_key.unwrap_or_default(),
            &nonce,
            add,
            &rest,
        )?;
        let mut out = Vec::new();
        out.extend_from_slice(add);
        out.extend_from_slice(&decoded);
        Ok(out)
    }

    /// Check an incoming message counter against this session's reception
    /// state. Must be called only after the message authenticated (decrypted
    /// successfully) so forged counters cannot poison the window.
    pub(crate) fn counter_is_new(&self, counter: u32) -> bool {
        self.reception_state.lock().unwrap().counter_is_new(counter)
    }

    fn make_nonce3(&self, counter: u32) -> Result<Vec<u8>> {
        Self::make_nonce3_extern(counter, self.local_node.as_deref())
    }

    fn make_nonce3_extern(counter: u32, node: Option<&[u8]>) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(128);
        out.write_u8(0)?;
        out.write_u32::<LittleEndian>(counter)?;
        match node {
            Some(s) => out.write_all(s)?,
            None => out.write_all(&[0, 0, 0, 0, 0, 0, 0, 0])?,
        };

        Ok(out)
    }
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::MessageReceptionState;

    #[test]
    fn in_order_and_duplicates() {
        let mut s = MessageReceptionState::default();
        assert!(s.counter_is_new(100));
        assert!(!s.counter_is_new(100));
        assert!(s.counter_is_new(101));
        assert!(s.counter_is_new(102));
        assert!(!s.counter_is_new(101));
        assert!(!s.counter_is_new(102));
    }

    #[test]
    fn reorder_within_window() {
        let mut s = MessageReceptionState::default();
        assert!(s.counter_is_new(100));
        assert!(s.counter_is_new(105));
        assert!(s.counter_is_new(103));
        assert!(s.counter_is_new(104));
        assert!(s.counter_is_new(101));
        assert!(s.counter_is_new(102));
        for c in 100..=105 {
            assert!(!s.counter_is_new(c), "counter {} must be duplicate", c);
        }
    }

    #[test]
    fn stale_beyond_window_rejected() {
        let mut s = MessageReceptionState::default();
        assert!(s.counter_is_new(1000));
        assert!(!s.counter_is_new(1000 - 33));
        assert!(!s.counter_is_new(900));
        assert!(s.counter_is_new(1000 - 32));
        assert!(!s.counter_is_new(1000 - 32));
    }

    #[test]
    fn window_shift_boundaries() {
        let mut s = MessageReceptionState::default();
        assert!(s.counter_is_new(100));
        assert!(s.counter_is_new(132));
        assert!(!s.counter_is_new(100));
        assert!(s.counter_is_new(101));

        let mut s = MessageReceptionState::default();
        assert!(s.counter_is_new(100));
        assert!(s.counter_is_new(133));
        assert!(!s.counter_is_new(100));
        assert!(!s.counter_is_new(133));
        assert!(s.counter_is_new(132));
    }

    #[test]
    fn large_jump_clears_window() {
        let mut s = MessageReceptionState::default();
        assert!(s.counter_is_new(100));
        assert!(s.counter_is_new(101));
        assert!(s.counter_is_new(1_000_000));
        assert!(s.counter_is_new(1_000_000 - 1));
        assert!(!s.counter_is_new(101));
    }

    #[test]
    fn mixed_sequence_bookkeeping() {
        let mut s = MessageReceptionState::default();
        assert!(s.counter_is_new(10));
        assert!(s.counter_is_new(12));
        assert!(!s.counter_is_new(12));
        assert!(s.counter_is_new(11));
        assert!(!s.counter_is_new(11));
        assert!(!s.counter_is_new(10));
        assert!(s.counter_is_new(13));
        assert!(!s.counter_is_new(12));
    }
}
