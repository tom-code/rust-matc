//! BLE scanner and GATT connector for Matter commissioning.
//!
//! Uses [`btleplug`] to scan for BLE-commissionable Matter devices
//!

#![cfg(feature = "ble")]

use std::time::Duration;

use anyhow::{bail, Context, Result};
use btleplug::{
    api::{
        Central, CentralEvent, Manager as _, Peripheral as _, ScanFilter, WriteType,
    },
    platform::{Manager, Peripheral},
};
use futures::StreamExt;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::btp::BlePeripheral;

pub const MATTER_SERVICE_UUID: Uuid = Uuid::from_u128(0x0000_fff6_0000_1000_8000_0080_5f9b_34fb);

pub const C1_UUID: Uuid = Uuid::from_u128(0x18ee_2ef5_263d_4559_959f_4f9c_429f_9d11);

pub const C2_UUID: Uuid = Uuid::from_u128(0x18ee_2ef5_263d_4559_959f_4f9c_429f_9d12);

/// Metadata extracted from a BLE advertisement.
#[derive(Debug, Clone)]
pub struct CommissionableDevice {
    pub discriminator: u16,
    pub vendor_id: u16,
    pub product_id: u16,
    /// Commissioning window is open (CM flag, bit 12 of service data).
    pub cm_flag: bool,
    /// Signal strength in dBm; closer to 0 is stronger.
    pub rssi: Option<i16>,
    /// BLE advertising name (often empty).
    pub name: Option<String>,
    /// TX power level in dBm; combine with `rssi` for path-loss estimation.
    pub tx_power: Option<i16>,
    /// Platform-specific peripheral identifier (UUID on macOS, MAC on Linux).
    pub address: String,
    pub peripheral: Peripheral,
}


pub async fn find_by_discriminator(discriminator: u16, short_match: bool, scan_timeout: Duration) -> Result<BlePeripheral> {
    let manager = Manager::new().await.context("BLE manager")?;
    let adapters = manager.adapters().await.context("listing BLE adapters")?;
    let central = adapters.into_iter().next().context("no BLE adapter found")?;

    let filter = ScanFilter {
        services: vec![MATTER_SERVICE_UUID],
    };
    central.start_scan(filter).await.context("start BLE scan")?;

    let mut events = central.events().await.context("BLE event stream")?;
    let deadline = tokio::time::Instant::now() + scan_timeout;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            bail!("BLE scan timeout: no device with discriminator {} found", discriminator);
        }
        let event = tokio::time::timeout(remaining, events.next())
            .await
            .context("BLE scan timeout")?
            .context("BLE event stream ended")?;

        match event {
            CentralEvent::DeviceDiscovered(id) | CentralEvent::DeviceUpdated(id) => {
                let peripheral = central.peripheral(&id).await?;
                let props = match peripheral.properties().await? {
                    Some(p) => p,
                    None => continue,
                };
                // Look for service data for our UUID
                let svc_data = props
                    .service_data
                    .get(&MATTER_SERVICE_UUID)
                    .cloned()
                    .unwrap_or_default();
                if svc_data.len() < 8 {
                    continue;
                }
                let (disc, vid, pid, cm_flag) = parse_service_data(&svc_data);
                log::debug!("BLE found device: disc={} vid={} pid={} cm={}", disc, vid, pid, cm_flag);
                let matches = if short_match {
                    disc >> 8 == discriminator >> 8
                } else {
                    disc == discriminator
                };
                if matches {
                    central.stop_scan().await.ok();
                    log::debug!("BLE device with matching discriminator found, connecting...");
                    return connect_peripheral(peripheral).await;
                }
            }
            _ => {}
        }
    }
}

pub async fn scan_commissionable(scan_timeout: Duration) -> Result<Vec<CommissionableDevice>> {
    let manager = Manager::new().await.context("BLE manager")?;
    let adapters = manager.adapters().await.context("listing BLE adapters")?;
    let central = adapters.into_iter().next().context("no BLE adapter found")?;

    log::debug!("Starting BLE scan for commissionable devices ({}s timeout)...", scan_timeout.as_secs());
    central.start_scan(ScanFilter { services: vec![MATTER_SERVICE_UUID] }).await?;
    log::debug!("Scanning for BLE devices...");
    tokio::time::sleep(scan_timeout).await;
    log::debug!("BLE scan complete, processing results...");
    central.stop_scan().await.ok();
    log::debug!("Retrieving discovered BLE peripherals...");

    let mut found = Vec::new();
    for peripheral in central.peripherals().await? {
        let props = match peripheral.properties().await? {
            Some(p) => p,
            None => continue,
        };
        if let Some(svc_data) = props.service_data.get(&MATTER_SERVICE_UUID) {
            if svc_data.len() >= 8 {
                let (disc, vid, pid, cm_flag) = parse_service_data(svc_data);
                found.push(CommissionableDevice {
                    discriminator: disc,
                    vendor_id: vid,
                    product_id: pid,
                    cm_flag,
                    rssi: props.rssi,
                    name: props.local_name.clone(),
                    tx_power: props.tx_power_level,
                    address: peripheral.id().to_string(),
                    peripheral,
                });
            }
        }
    }
    Ok(found)
}


/// Parse a Matter BLE advertisement service-data payload.
/// Returns `(discriminator, vendor_id, product_id, cm_flag)`.
fn parse_service_data(data: &[u8]) -> (u16, u16, u16, bool) {
    let disc_raw = (data[1] as u16) | ((data[2] as u16) << 8);
    let discriminator = disc_raw & 0x0fff;
    let cm_flag = (disc_raw >> 12) & 0x1 != 0;
    let vid = if data.len() >= 5 {
        (data[3] as u16) | ((data[4] as u16) << 8)
    } else {
        0
    };
    let pid = if data.len() >= 7 {
        (data[5] as u16) | ((data[6] as u16) << 8)
    } else {
        0
    };
    (discriminator, vid, pid, cm_flag)
}

/// Connect to a peripheral, discover BTP characteristics, and return a
/// [`BlePeripheral`] with the C1/C2 channels wired up.
pub async fn connect_peripheral(peripheral: Peripheral) -> Result<BlePeripheral> {
    peripheral.connect().await.context("BLE connect")?;
    log::debug!("BLE: connected, discovering services...");
    peripheral.discover_services().await.context("BLE discover_services")?;

    let chars = peripheral.characteristics();
    let c1 = chars
        .iter()
        .find(|c| c.uuid == C1_UUID)
        .cloned()
        .context("BLE: C1 characteristic not found")?;
    let c2 = chars
        .iter()
        .find(|c| c.uuid == C2_UUID)
        .cloned()
        .context("BLE: C2 characteristic not found")?;
    log::debug!("BLE: C1 props={:?} C2 props={:?}", c1.properties, c2.properties);

    let mut notifs = peripheral.notifications().await.context("C2 notifications")?;

    // Wrap in mpsc channels so BtpConnection is not tied to btleplug types.
    let (write_tx, mut write_rx) = mpsc::channel::<Vec<u8>>(64);
    let (read_tx, read_rx) = mpsc::channel::<Vec<u8>>(64);

    let periph_write = peripheral.clone();
    let c1_clone = c1.clone();
    let c2_clone = c2.clone();
    tokio::spawn(async move {
        let mut first = true;
        while let Some(data) = write_rx.recv().await {
            log::debug!("BLE C1 write ({} bytes): {}", data.len(), hex_dump(&data));
            if let Err(e) = periph_write.write(&c1_clone, &data, WriteType::WithResponse).await {
                log::warn!("BLE C1 write error: {:?}", e);
                break;
            }
            if first {
                first = false;
                log::debug!("BLE: enabling C2 indications after handshake write...");
                if let Err(e) = periph_write.subscribe(&c2_clone).await {
                    log::warn!("BLE C2 subscribe error: {:?}", e);
                    break;
                }
                log::debug!("BLE: C2 subscribed");
            }
        }
    });

    let c2_handle = tokio::spawn(async move {
        log::debug!("BLE: waiting for C2 notifications...");
        while let Some(notif) = notifs.next().await {
            log::debug!(
                "BLE notification uuid={} ({} bytes): {}",
                notif.uuid,
                notif.value.len(),
                hex_dump(&notif.value),
            );
            if notif.uuid == C2_UUID
                && read_tx.send(notif.value).await.is_err() {
                    break;
                }
        }
        log::debug!("BLE C2 notification stream ended");
    });
    let c2_abort = c2_handle.abort_handle();

    let periph_disconnect = peripheral.clone();
    let disconnect = Box::new(move || {
        tokio::spawn(async move {
            log::debug!("BTP: disconnecting BLE peripheral");
            let _ = periph_disconnect.disconnect().await;
        });
    }) as Box<dyn FnOnce() + Send>;

    // how to get negotiated mtu? change to 23?
    let att_mtu: usize = 185;

    Ok(BlePeripheral {
        write_c1: write_tx,
        read_c2: read_rx,
        att_mtu,
        c2_abort,
        disconnect,
    })
}

fn hex_dump(data: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(data.len() * 3);
    for b in data {
        let _ = write!(s, "{:02x} ", b);
    }
    s.trim_end().to_string()
}
