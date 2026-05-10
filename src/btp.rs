//! Bluetooth Transport Protocol (BTP) - Matter over BLE.


#![cfg(feature = "ble")]

use std::{collections::VecDeque, sync::Arc, time::Duration};

use anyhow::{bail, Context, Result};
use tokio::{
    sync::{mpsc, Mutex},
    time::timeout,
};

use crate::transport::{ConnectionTrait};

const BTP_VERSION: u8 = 4;
const BTP_WINDOW_SIZE: u8 = 6;
const KEEPALIVE: Duration = Duration::from_secs(5);

const F_HANDSHAKE: u8 = 1 << 6;
const F_MGMT: u8 = 1 << 5;
const F_ACK: u8 = 1 << 3;
const F_END: u8 = 1 << 2;
const F_CONT: u8 = 1 << 1;
const F_BEGIN: u8 = 1;

pub struct BlePeripheral {
    pub write_c1: mpsc::Sender<Vec<u8>>,
    pub read_c2: mpsc::Receiver<Vec<u8>>,
    pub att_mtu: usize,
}


pub struct BtpConnection {
    incoming: Mutex<mpsc::Receiver<Vec<u8>>>,
    outgoing: mpsc::Sender<Vec<BtpSegment>>,
    mtu_payload: usize,
}

struct BtpSegment {
    flags: u8,
    seq: u8,
    ack: Option<u8>,
    begin_len: Option<u16>,
    payload: Vec<u8>,
}

impl BtpSegment {
    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.flags);
        if let Some(a) = self.ack {
            buf.push(a);
        }
        buf.push(self.seq);
        if let Some(l) = self.begin_len {
            buf.push((l & 0xff) as u8);
            buf.push((l >> 8) as u8);
        }
        buf.extend_from_slice(&self.payload);
        buf
    }

    fn decode(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            bail!("empty BTP segment");
        }
        let flags = data[0];
        if flags & (F_HANDSHAKE | F_MGMT) != 0 {
            bail!("unexpected handshake/mgmt frame in steady state");
        }
        let mut i = 1usize;
        let ack = if flags & F_ACK != 0 {
            let a = *data.get(i).context("truncated: ack")?;
            i += 1;
            Some(a)
        } else {
            None
        };
        let seq = *data.get(i).context("truncated: seq")?;
        i += 1;
        let begin_len = if flags & F_BEGIN != 0 {
            let lo = *data.get(i).context("truncated: begin_len lo")?;
            let hi = *data.get(i + 1).context("truncated: begin_len hi")?;
            i += 2;
            Some((lo as u16) | ((hi as u16) << 8))
        } else {
            None
        };
        Ok(Self {
            flags,
            seq,
            ack,
            begin_len,
            payload: data[i..].to_vec(),
        })
    }
}

impl BtpConnection {
    /// Run the BTP handshake over peripheral and return a ready connection.
    pub async fn connect(mut peripheral: BlePeripheral) -> Result<Arc<Self>> {
        log::debug!("BTP: sending handshake request");
        let handshake_req = build_handshake_req(peripheral.att_mtu as u16, BTP_WINDOW_SIZE);
        peripheral.write_c1.send(handshake_req).await.context("BTP: handshake write")?;
        log::debug!("BTP: waiting for handshake response...");
        let resp_bytes = timeout(Duration::from_secs(10), peripheral.read_c2.recv())
            .await
            .context("BTP: handshake timeout")?
            .context("BTP: C2 stream closed during handshake")?;
        let (negotiated_mtu, window) = parse_handshake_resp(&resp_bytes)?;
        log::info!("BTP handshake: payload_mtu={} window={}", negotiated_mtu, window);

        let (incoming_tx, incoming_rx) = mpsc::channel::<Vec<u8>>(32);
        let (outgoing_tx, outgoing_rx) = mpsc::channel::<Vec<BtpSegment>>(64);

        let c1 = peripheral.write_c1;
        let c2 = peripheral.read_c2;
        tokio::spawn(async move {
            if let Err(e) = io_loop(c1, c2, incoming_tx, outgoing_rx, window).await {
                log::warn!("BTP io_loop: {:?}", e);
            }
        });

        Ok(Arc::new(Self {
            incoming: Mutex::new(incoming_rx),
            outgoing: outgoing_tx,
            mtu_payload: negotiated_mtu,
        }))
    }
}

#[async_trait::async_trait]
impl ConnectionTrait for BtpConnection {
    async fn send(&self, data: &[u8]) -> Result<()> {
        let segs = segment(data, self.mtu_payload);
        self.outgoing
            .send(segs)
            .await
            .map_err(|_| anyhow::anyhow!("BTP outgoing channel closed"))
    }

    async fn receive(&self, tmout: Duration) -> Result<Vec<u8>> {
        let mut rx = self.incoming.lock().await;
        let msg = timeout(tmout, rx.recv())
            .await
            .context("BTP receive timeout")?
            .context("BTP connection closed")?;
        Ok(msg)
    }

    fn is_reliable(&self) -> bool { true }
}

fn build_handshake_req(mtu: u16, window: u8) -> Vec<u8> {
    vec![
        F_HANDSHAKE | F_MGMT | F_BEGIN | F_END,
        0x6C,                       // BTP Handshake Request opcode
        BTP_VERSION,                // Version0 (lo) = 4, Version1 (hi) = 0
        0x00,                       // Version3 | Version2
        0x00,                       // Version5 | Version4
        0x00,                       // Version7 | Version6
        (mtu & 0xff) as u8,         // ATT_MTU low byte  (LE)
        (mtu >> 8) as u8,           // ATT_MTU high byte (LE)
        window,
    ]
}

fn parse_handshake_resp(data: &[u8]) -> Result<(usize, u8)> {
    if data.len() < 6 {
        bail!("BTP handshake response too short ({} bytes)", data.len());
    }
    if data[0] & (F_HANDSHAKE | F_MGMT) == 0 {
        bail!("BTP handshake resp: bad flags 0x{:02X}", data[0]);
    }
    if data[1] != 0x6C {
        bail!("BTP handshake resp: unexpected opcode 0x{:02X}", data[1]);
    }
    let mtu = ((data[3] as usize) | ((data[4] as usize) << 8)).saturating_sub(3).max(20);
    Ok((mtu, data[5]))
}

fn segment(msg: &[u8], mtu: usize) -> Vec<BtpSegment> {
    // Overhead per frame:
    //   flags(1) + ack(1, if F_ACK set) + seq(1) + begin_len(2, if F_BEGIN)
    // We always include F_ACK so overhead = flags+ack+seq = 3, +2 for first frame.
    let first_max = mtu.saturating_sub(5).max(1);
    let cont_max  = mtu.saturating_sub(3).max(1);
    let total = msg.len();
    let mut out = Vec::new();
    let mut offset = 0;
    let mut first = true;

    while offset < total {
        let limit = if first { first_max } else { cont_max };
        let end = (offset + limit).min(total);
        let last = end == total;
        let chunk = msg[offset..end].to_vec();

        let mut flags = /*F_ACK*/0;
        if first { flags |= F_BEGIN; }
        if !first && !last { flags |= F_CONT; }
        if last { flags |= F_END; }
        let ac = {
            if first { Some(total as u8) } else { None }
        };
        out.push(BtpSegment {
            flags,
            seq: 0,                          // filled by io_loop
            ack: ac,                         // filled by io_loop
            begin_len: if first { Some(total as u16) } else { None },
            payload: chunk,
        });

        offset = end;
        first = false;
    }
    out
}


struct State {
    my_seq: u8,
    remote_seq: u8,
    last_sent_ack: u8,
    window: u8,
    unacked: u8,
    rx_buf: Vec<u8>,
    rx_expected: usize,
    tx_queue: VecDeque<BtpSegment>,
}

impl State {
    fn new(window: u8) -> Self {
        Self {
            my_seq: 0,
            remote_seq: 0,
            last_sent_ack: 0,
            window,
            unacked: 0,
            rx_buf: Vec::new(),
            rx_expected: 0,
            tx_queue: VecDeque::new(),
        }
    }

    fn enqueue(&mut self, segs: Vec<BtpSegment>) {
        for s in segs {
            self.tx_queue.push_back(s);
        }
    }

    fn pop_sendable(&mut self) -> Option<Vec<u8>> {
        if self.unacked >= self.window {
            log::debug!(
                "BTP tx blocked: unacked={}/{} queued={}",
                self.unacked, self.window, self.tx_queue.len()
            );
            return None;
        }
        if self.tx_queue.is_empty() {
            return None;
        }
        let mut seg = self.tx_queue.pop_front().unwrap();
        seg.seq = self.my_seq;
        if seg.ack.is_some() {
            seg.ack = Some(self.remote_seq);
            seg.flags |= F_ACK;
        }
        self.last_sent_ack = self.remote_seq;
        self.my_seq = self.my_seq.wrapping_add(1);
        self.unacked += 1;
        log::debug!(
            "BTP tx seg: flags=0x{:02x} seq={} ack={:?} payload={}B unacked={}/{}",
            seg.flags, seg.seq, seg.ack, seg.payload.len(),
            self.unacked, self.window
        );
        Some(seg.encode())
    }

    fn process_rx(&mut self, data: &[u8]) -> Result<Option<Vec<u8>>> {
        let seg = BtpSegment::decode(data)?;
        let prev_unacked = self.unacked;
        if let Some(ack) = seg.ack {
            // Count how many of our sent segments this ACK covers.
            let delta = ack.wrapping_sub(self.my_seq.wrapping_sub(self.unacked)).wrapping_add(1);
            let credited = delta.min(self.unacked);
            self.unacked = self.unacked.saturating_sub(credited);
        }
        log::debug!(
            "BTP rx seg: flags=0x{:02x} seq={} ack={:?} payload={}B unacked {}->{}",
            seg.flags, seg.seq, seg.ack, seg.payload.len(),
            prev_unacked, self.unacked
        );
        self.remote_seq = seg.seq;
        if seg.flags & F_BEGIN != 0 {
            self.rx_buf.clear();
            self.rx_expected = seg.begin_len.unwrap_or(0) as usize;
        }
        self.rx_buf.extend_from_slice(&seg.payload);
        if seg.flags & F_END != 0 && !self.rx_buf.is_empty() {
            return Ok(Some(std::mem::take(&mut self.rx_buf)));
        }
        Ok(None)
    }

    fn needs_ack(&self) -> bool {
        self.last_sent_ack != self.remote_seq
    }

    fn standalone_ack(&mut self) -> Vec<u8> {
        let bytes = BtpSegment {
            flags: F_ACK,
            seq: self.my_seq,
            ack: Some(self.remote_seq),
            begin_len: None,
            payload: vec![],
        }.encode();
        self.last_sent_ack = self.remote_seq;
        self.my_seq = self.my_seq.wrapping_add(1);
        bytes
    }
}

async fn io_loop(
    write_c1: mpsc::Sender<Vec<u8>>,
    mut read_c2: mpsc::Receiver<Vec<u8>>,
    incoming_tx: mpsc::Sender<Vec<u8>>,
    mut outgoing_rx: mpsc::Receiver<Vec<BtpSegment>>,
    window: u8,
) -> Result<()> {
    let mut state = State::new(window);
    let mut keepalive = tokio::time::interval(KEEPALIVE);

    loop {
        // Flush sendable frames.
        while let Some(frame) = state.pop_sendable() {
            write_c1.send(frame).await.context("C1 write")?;
        }

        tokio::select! {
            // New outbound message segments from BtpConnection::send
            segs = outgoing_rx.recv() => {
                match segs {
                    Some(s) => state.enqueue(s),
                    None => bail!("outgoing channel closed"),
                }
            }

            // Inbound data from C2 indications
            data = read_c2.recv() => {
                match data {
                    Some(d) => {
                        match state.process_rx(&d) {
                            Ok(Some(msg)) => {
                                incoming_tx.send(msg).await.context("incoming channel")?;
                            }
                            Ok(None) => {}
                            Err(e) => log::warn!("BTP rx error: {:?}", e),
                        }
                    }
                    None => bail!("C2 stream ended"),
                }
            }

            // Keepalive tick - send standalone ack if needed
            _ = keepalive.tick() => {
                if state.needs_ack() {
                    let ack = state.standalone_ack();
                    write_c1.send(ack).await.context("keepalive ack")?;
                }
            }
        }

        // Flush again after receiving.
        while let Some(frame) = state.pop_sendable() {
            write_c1.send(frame).await.context("C1 write post-rx")?;
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_encode() {
        let req = build_handshake_req(247, 8);
        assert_eq!(req.len(), 9);
        assert_eq!(req[0], F_HANDSHAKE | F_MGMT | F_BEGIN | F_END);
        assert_eq!(req[1], 0x6C);
        assert_eq!(req[2], BTP_VERSION);
        assert_eq!(req[3], 0x00);
        assert_eq!(req[4], 0x00);
        assert_eq!(req[5], 0x00);
        // ATT_MTU is LE: low byte at [6], high byte at [7]
        assert_eq!(req[6], (247 & 0xff) as u8);
        assert_eq!(req[7], (247 >> 8) as u8);
        assert_eq!((req[6] as u16) | ((req[7] as u16) << 8), 247);
        assert_eq!(req[8], 8);
    }

    #[test]
    fn test_handshake_resp_parse() {
        // Response format (6 bytes): flags, opcode, version, mtu_lo, mtu_hi, window
        let resp = [F_HANDSHAKE | F_MGMT | F_BEGIN | F_END, 0x6C, 0x04, 200, 0, 6];
        let (mtu, window) = parse_handshake_resp(&resp).unwrap();
        assert_eq!(mtu, 197); // 200 - 3
        assert_eq!(window, 6);
    }

    #[test]
    fn test_segment_encode_decode_single() {
        let msg = b"hello world";
        let segs = segment(msg, 64);
        assert_eq!(segs.len(), 1);
        // Capture before enqueuing - enqueue moves the vec.
        let expected_payload: Vec<u8> = msg.to_vec();
        let expected_begin_len = segs[0].begin_len;
        assert!(segs[0].flags & F_BEGIN != 0);
        assert!(segs[0].flags & F_END != 0);
        assert_eq!(expected_begin_len, Some(msg.len() as u16));
        assert_eq!(segs[0].payload, msg as &[u8]);
        // segment() returns placeholder seq/ack - route through State::pop_sendable
        // so that seq and F_ACK are set consistently before encoding.
        let mut state = State::new(8);
        state.enqueue(segs);
        let enc = state.pop_sendable().unwrap();
        let dec = BtpSegment::decode(&enc).unwrap();
        assert!(dec.flags & F_BEGIN != 0);
        assert!(dec.flags & F_END != 0);
        assert_eq!(dec.seq, 0);
        assert_eq!(dec.begin_len, expected_begin_len);
        assert_eq!(dec.payload, expected_payload);
    }

    #[test]
    fn test_segment_multi_and_reassemble() {
        let msg: Vec<u8> = (0u8..=99).collect();
        let segs = segment(&msg, 20);
        assert!(segs.len() > 1);
        assert!(segs[0].flags & F_BEGIN != 0);
        assert!(segs.last().unwrap().flags & F_END != 0);

        // Route through State on both sides so seq/ack/F_ACK are consistent.
        let mut tx = State::new(8);
        tx.enqueue(segs);
        let mut rx = State::new(8);
        let mut result = None;
        while let Some(enc) = tx.pop_sendable() {
            result = rx.process_rx(&enc).unwrap();
        }
        assert_eq!(result.unwrap(), msg);
    }
}
