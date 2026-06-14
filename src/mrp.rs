//! Message Reliability Protocol (MRP) timing parameters and backoff math
//! per Matter specification section 4.12.
//!
//! Peers advertise their session intervals in mDNS TXT records (keys SII,
//! SAI, SAT - decimal milliseconds). Senders derive retransmission deadlines
//! from these values using exponential backoff with jitter:
//!
//! `t = i * MARGIN * BASE^max(0, n - THRESHOLD) * (1 + rand * JITTER)`
//!
//! where `i` is the peer's active interval (SAI) if the peer was heard from
//! within the active threshold (SAT), otherwise its idle interval (SII), and
//! `n` is the 0-based retransmission index. A message is given up on after
//! [`MRP_MAX_TRANSMISSIONS`] total transmissions.
//!
//! Used by [`crate::retransmit`] (handshake exchanges) and
//! [`crate::active_connection`] (operational traffic). Parameters are stored
//! on the transport connection ([`crate::transport::ConnectionTrait::mrp_params`]).

use std::time::Duration;

/// Maximum number of transmissions of a single message (initial + retransmits).
pub const MRP_MAX_TRANSMISSIONS: u32 = 5;
pub const MRP_BACKOFF_MARGIN: f64 = 1.1;
pub const MRP_BACKOFF_BASE: f64 = 1.6;
pub const MRP_BACKOFF_THRESHOLD: u32 = 1;
pub const MRP_BACKOFF_JITTER: f64 = 0.25;
/// Spec cap for advertised SII/SAI values (milliseconds).
pub const MRP_MAX_INTERVAL_MS: u32 = 3_600_000;

const DEFAULT_IDLE_INTERVAL_MS: u32 = 500;
const DEFAULT_ACTIVE_INTERVAL_MS: u32 = 300;
const DEFAULT_ACTIVE_THRESHOLD_MS: u32 = 4000;

/// Peer MRP intervals, typically taken from its mDNS TXT records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MrpParameters {
    /// SII - retransmission interval when the peer is idle (sleepy).
    pub session_idle_interval: Duration,
    /// SAI - retransmission interval when the peer is active.
    pub session_active_interval: Duration,
    /// SAT - how long after the last received message the peer counts as active.
    pub session_active_threshold: Duration,
}

impl Default for MrpParameters {
    fn default() -> Self {
        Self {
            session_idle_interval: Duration::from_millis(DEFAULT_IDLE_INTERVAL_MS as u64),
            session_active_interval: Duration::from_millis(DEFAULT_ACTIVE_INTERVAL_MS as u64),
            session_active_threshold: Duration::from_millis(DEFAULT_ACTIVE_THRESHOLD_MS as u64),
        }
    }
}

impl MrpParameters {
    /// Build from optional TXT-record millisecond values (keys SII/SAI/SAT).
    /// Missing values fall back to spec defaults; SII/SAI are clamped to
    /// [`MRP_MAX_INTERVAL_MS`].
    pub fn from_txt_ms(sii: Option<u32>, sai: Option<u32>, sat: Option<u32>) -> Self {
        let clamp = |v: u32| v.min(MRP_MAX_INTERVAL_MS) as u64;
        Self {
            session_idle_interval: Duration::from_millis(clamp(
                sii.unwrap_or(DEFAULT_IDLE_INTERVAL_MS),
            )),
            session_active_interval: Duration::from_millis(clamp(
                sai.unwrap_or(DEFAULT_ACTIVE_INTERVAL_MS),
            )),
            session_active_threshold: Duration::from_millis(
                sat.unwrap_or(DEFAULT_ACTIVE_THRESHOLD_MS) as u64,
            ),
        }
    }
}

/// Base retransmission interval: the peer's active interval if it was heard
/// from within the active threshold, otherwise its idle interval.
pub fn base_interval(params: &MrpParameters, last_rx_elapsed: Option<Duration>) -> Duration {
    match last_rx_elapsed {
        Some(elapsed) if elapsed < params.session_active_threshold => {
            params.session_active_interval
        }
        _ => params.session_idle_interval,
    }
}

/// Wait time before the next retransmission per spec 4.12 backoff formula.
/// `retransmission_index` is 0 for the wait after the initial transmission.
pub fn backoff_interval(base: Duration, retransmission_index: u32) -> Duration {
    let exponent = retransmission_index.saturating_sub(MRP_BACKOFF_THRESHOLD);
    let t = base.as_secs_f64()
        * MRP_BACKOFF_MARGIN
        * MRP_BACKOFF_BASE.powi(exponent as i32)
        * (1.0 + rand::random::<f64>() * MRP_BACKOFF_JITTER);
    Duration::from_secs_f64(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_defaults() {
        let p = MrpParameters::default();
        assert_eq!(p.session_idle_interval, Duration::from_millis(500));
        assert_eq!(p.session_active_interval, Duration::from_millis(300));
        assert_eq!(p.session_active_threshold, Duration::from_millis(4000));
        assert_eq!(p, MrpParameters::from_txt_ms(None, None, None));
    }

    #[test]
    fn test_from_txt_ms_clamps() {
        let p = MrpParameters::from_txt_ms(Some(4_000_000), Some(300), Some(4000));
        assert_eq!(
            p.session_idle_interval,
            Duration::from_millis(MRP_MAX_INTERVAL_MS as u64)
        );
        let p = MrpParameters::from_txt_ms(Some(5000), None, None);
        assert_eq!(p.session_idle_interval, Duration::from_millis(5000));
        assert_eq!(p.session_active_interval, Duration::from_millis(300));
    }

    #[test]
    fn test_base_interval_selection() {
        let p = MrpParameters::default();
        assert_eq!(base_interval(&p, None), p.session_idle_interval);
        assert_eq!(
            base_interval(&p, Some(Duration::from_millis(1000))),
            p.session_active_interval
        );
        assert_eq!(
            base_interval(&p, Some(Duration::from_millis(4000))),
            p.session_idle_interval
        );
    }

    #[test]
    fn test_backoff_interval_bounds() {
        let base = Duration::from_millis(500);
        let mut prev_lower = 0.0f64;
        for n in 0..MRP_MAX_TRANSMISSIONS {
            let exponent = n.saturating_sub(MRP_BACKOFF_THRESHOLD);
            let lower = 0.5 * MRP_BACKOFF_MARGIN * MRP_BACKOFF_BASE.powi(exponent as i32);
            let upper = lower * (1.0 + MRP_BACKOFF_JITTER);
            for _ in 0..50 {
                let t = backoff_interval(base, n).as_secs_f64();
                assert!(t >= lower - 1e-9, "n={} t={} lower={}", n, t, lower);
                assert!(t <= upper + 1e-9, "n={} t={} upper={}", n, t, upper);
            }
            assert!(lower >= prev_lower);
            prev_lower = lower;
        }
    }
}
