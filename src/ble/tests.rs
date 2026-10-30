use std::{collections::HashMap, time::Duration};

use btleplug::api::{PeripheralProperties, ScanFilter};

use super::{find_by_discriminator, scan_commissionable, MATTER_SERVICE_UUID};
use backend::{Call, CentralEvent, Device, State};
use fixtures::{raw_advertisement, raw_device, TestDeviceDefinition};

pub(super) mod backend;
mod fixtures;

// Independent vectors retained from the original PR, not verified device captures.
// OpCode, discriminator + advertisement version (LE), VID (LE), PID (LE), flags.
const MATTER_SERVICE_DATA_ABC: [u8; 8] = [0x00, 0xbc, 0x0a, 0x2f, 0x13, 0x0d, 0x02, 0x00];
const MATTER_SERVICE_DATA_560: [u8; 8] = [0x00, 0x60, 0x05, 0x2f, 0x13, 0x0d, 0x02, 0x00];
const TIMEOUT: Duration = Duration::from_secs(30);

fn finish(result: anyhow::Result<crate::btp::BlePeripheral>) {
    // No BTP handshake is run; stop the notification task created by connect_peripheral.
    let peripheral = result.unwrap();
    peripheral.c2_abort.abort();
    (peripheral.disconnect)();
}

#[tokio::test(start_paused = true)]
async fn find_skips_disappeared_peripheral_and_unreadable_properties() {
    let unreadable = TestDeviceDefinition {
        id: 2,
        discriminator: 0x0123,
        ..Default::default()
    };
    let target = TestDeviceDefinition {
        id: 3,
        discriminator: 0x0abc,
        ..Default::default()
    };
    let mut state = State {
        events: vec![
            CentralEvent::DeviceDiscovered(1),
            CentralEvent::DeviceUpdated(unreadable.id),
            CentralEvent::DeviceDiscovered(target.id),
        ],
        ..Default::default()
    };
    state.devices.insert(
        unreadable.id,
        Device {
            properties_failures: 1,
            ..unreadable.device()
        },
    );
    state.devices.insert(target.id, target.device());

    let (result, state) = backend::run(state, find_by_discriminator(0x0abc, false, TIMEOUT)).await;
    finish(result);
    assert_eq!(
        state.lock().unwrap().calls,
        vec![
            Call::Events,
            Call::Start(ScanFilter::default()),
            Call::Lookup(1),
            Call::Lookup(2),
            Call::Properties(2),
            Call::Lookup(3),
            Call::Properties(3),
            Call::Stop,
            Call::Connect(3),
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn find_retries_later_advertisement_after_failed_lookup() {
    let target = TestDeviceDefinition {
        id: 1,
        discriminator: 0x0abc,
        ..Default::default()
    };
    let mut state = State {
        events: vec![target.advertisement(), target.advertisement()],
        ..Default::default()
    };
    state.devices.insert(
        target.id,
        Device {
            lookup_failures: 1,
            ..Default::default()
        },
    );

    let (result, state) = backend::run(state, find_by_discriminator(0x0abc, false, TIMEOUT)).await;
    finish(result);
    assert_eq!(
        state.lock().unwrap().calls,
        vec![
            Call::Events,
            Call::Start(ScanFilter::default()),
            Call::Lookup(1),
            Call::Lookup(1),
            Call::Stop,
            Call::Connect(1),
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn find_filters_fixed_service_data_vectors_before_looking_up_peripheral() {
    for (data, discriminator, short_match) in [
        (MATTER_SERVICE_DATA_ABC, 0x0abc, false),
        (MATTER_SERVICE_DATA_ABC, 0x0a00, true),
        (MATTER_SERVICE_DATA_560, 0x0500, true),
    ] {
        let mut wrong = data;
        wrong[1] ^= 1;
        if short_match {
            wrong[2] = 0x0b;
        }
        let mut state = State {
            events: vec![
                CentralEvent::Other,
                CentralEvent::ServiceDataAdvertisement {
                    id: 1,
                    service_data: HashMap::new(),
                },
                raw_advertisement(1, &data[..7]),
                raw_advertisement(1, &wrong),
                raw_advertisement(2, &data),
            ],
            ..Default::default()
        };
        // Service-data-only device: there are no cached properties or discovery events.
        state.devices.insert(2, Device::default());
        let (result, state) = backend::run(
            state,
            find_by_discriminator(discriminator, short_match, TIMEOUT),
        )
        .await;
        finish(result);
        assert_eq!(
            state.lock().unwrap().calls,
            vec![
                Call::Events,
                Call::Start(ScanFilter::default()),
                Call::Lookup(2),
                Call::Stop,
                Call::Connect(2),
            ]
        );
    }
}

#[tokio::test(start_paused = true)]
async fn find_stops_after_timeout_even_when_candidates_fail() {
    let state = State {
        events: vec![CentralEvent::DeviceDiscovered(1)],
        ..Default::default()
    };
    let before = tokio::time::Instant::now();
    let (result, state) = backend::run(state, find_by_discriminator(0x0abc, false, TIMEOUT)).await;
    assert!(result
        .err()
        .unwrap()
        .to_string()
        .contains("BLE scan timeout"));
    assert_eq!(before.elapsed(), TIMEOUT);
    assert_eq!(state.lock().unwrap().calls.last(), Some(&Call::Stop));
}

#[tokio::test(start_paused = true)]
async fn find_preserves_scan_and_stream_errors() {
    for (state, message, stops) in [
        (
            State {
                events_error: true,
                ..Default::default()
            },
            "BLE event stream",
            false,
        ),
        (
            State {
                start_error: true,
                ..Default::default()
            },
            "start BLE scan",
            false,
        ),
        (
            State {
                end_events: true,
                ..Default::default()
            },
            "BLE event stream ended",
            true,
        ),
    ] {
        let (result, state) =
            backend::run(state, find_by_discriminator(0x0abc, false, TIMEOUT)).await;
        assert_eq!(result.err().unwrap().to_string(), message);
        assert_eq!(state.lock().unwrap().calls.contains(&Call::Stop), stops);
    }
}

#[tokio::test(start_paused = true)]
async fn find_preserves_connection_errors() {
    let target = TestDeviceDefinition {
        id: 1,
        discriminator: 0x0abc,
        ..Default::default()
    };
    let mut state = State {
        events: vec![target.advertisement()],
        ..Default::default()
    };
    state.devices.insert(
        target.id,
        Device {
            connect_error: true,
            ..Default::default()
        },
    );
    let (result, state) = backend::run(state, find_by_discriminator(0x0abc, false, TIMEOUT)).await;
    assert_eq!(result.err().unwrap().to_string(), "BLE connect");
    assert!(state
        .lock()
        .unwrap()
        .calls
        .ends_with(&[Call::Stop, Call::Connect(1)]));
}

#[tokio::test(start_paused = true)]
async fn scan_includes_service_data_only_devices_and_skips_bad_candidates() {
    let mut state = State::default();
    state.devices.insert(
        1,
        Device {
            properties_failures: 1,
            ..Default::default()
        },
    );
    let target = TestDeviceDefinition {
        id: 2,
        discriminator: 0x0abc,
        vendor_id: 0x1234,
        product_id: 0x0042,
        name: Some("Matter test device".to_owned()),
        rssi: Some(-60),
        tx_power: Some(-4),
        ..Default::default()
    };
    assert!(target.advertised_services.is_empty());
    state.devices.insert(target.id, target.device());
    state.devices.insert(
        3,
        Device {
            properties: Some(PeripheralProperties::default()),
            ..Default::default()
        },
    );
    state
        .devices
        .insert(4, raw_device(&MATTER_SERVICE_DATA_ABC[..7]));
    state.devices.insert(5, Device::default());

    let before = tokio::time::Instant::now();
    let (result, state) = backend::run(state, scan_commissionable(TIMEOUT)).await;
    let found = result.unwrap();
    assert_eq!(before.elapsed(), TIMEOUT);
    assert_eq!(found.len(), 1);
    let found = &found[0];
    assert_eq!(found.discriminator, 0x0abc);
    assert_eq!(found.vendor_id, 0x1234);
    assert_eq!(found.product_id, 0x0042);
    assert_eq!(found.name.as_deref(), Some("Matter test device"));
    assert_eq!(found.rssi, Some(-60));
    assert_eq!(found.tx_power, Some(-4));
    assert_eq!(found.address, "2");
    assert_eq!(found.peripheral.id(), 2);
    assert_eq!(
        state.lock().unwrap().calls,
        vec![
            Call::Start(ScanFilter::default()),
            Call::Stop,
            Call::List,
            Call::Properties(1),
            Call::Properties(2),
            Call::Properties(3),
            Call::Properties(4),
            Call::Properties(5),
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn scan_with_no_devices_returns_an_empty_list() {
    let (result, state) = backend::run(State::default(), scan_commissionable(TIMEOUT)).await;
    assert!(result.unwrap().is_empty());
    assert_eq!(
        state.lock().unwrap().calls,
        vec![Call::Start(ScanFilter::default()), Call::Stop, Call::List,]
    );
}

#[tokio::test(start_paused = true)]
async fn scan_preserves_start_and_enumeration_errors() {
    let (result, state) = backend::run(
        State {
            start_error: true,
            ..Default::default()
        },
        scan_commissionable(TIMEOUT),
    )
    .await;
    assert_eq!(result.err().unwrap().to_string(), "start BLE scan");
    assert_eq!(
        state.lock().unwrap().calls,
        vec![Call::Start(ScanFilter::default())]
    );

    let (result, state) = backend::run(
        State {
            list_error: true,
            ..Default::default()
        },
        scan_commissionable(TIMEOUT),
    )
    .await;
    assert_eq!(result.err().unwrap().to_string(), "Permission denied");
    assert_eq!(
        state.lock().unwrap().calls,
        vec![Call::Start(ScanFilter::default()), Call::Stop, Call::List,]
    );
}

#[tokio::test(start_paused = true)]
async fn find_warns_when_stop_fails_without_blocking_connection() {
    let target = TestDeviceDefinition {
        id: 1,
        discriminator: 0x0abc,
        ..Default::default()
    };
    let mut state = State {
        events: vec![target.advertisement()],
        stop_error: true,
        ..Default::default()
    };
    state.devices.insert(target.id, Device::default());
    let (result, state) = backend::run(state, find_by_discriminator(0x0abc, false, TIMEOUT)).await;
    finish(result);
    let state = state.lock().unwrap();
    assert!(state.calls.ends_with(&[Call::Stop, Call::Connect(1)]));
    assert_eq!(
        state.warnings,
        vec!["BLE stop_scan failed: PermissionDenied"]
    );
}

#[tokio::test(start_paused = true)]
async fn find_warns_when_stop_fails_without_masking_search_or_connection_errors() {
    for end_events in [false, true] {
        let state = State {
            stop_error: true,
            end_events,
            ..Default::default()
        };
        let (result, state) =
            backend::run(state, find_by_discriminator(0x0abc, false, TIMEOUT)).await;
        let expected = if end_events {
            "BLE event stream ended"
        } else {
            "BLE scan timeout"
        };
        assert_eq!(result.err().unwrap().to_string(), expected);
        assert_eq!(
            state.lock().unwrap().warnings,
            vec!["BLE stop_scan failed: PermissionDenied"]
        );
    }

    let target = TestDeviceDefinition {
        id: 1,
        discriminator: 0x0abc,
        ..Default::default()
    };
    let mut state = State {
        events: vec![target.advertisement()],
        stop_error: true,
        ..Default::default()
    };
    state.devices.insert(
        target.id,
        Device {
            connect_error: true,
            ..Default::default()
        },
    );
    let (result, state) = backend::run(state, find_by_discriminator(0x0abc, false, TIMEOUT)).await;
    assert_eq!(result.err().unwrap().to_string(), "BLE connect");
    assert_eq!(
        state.lock().unwrap().warnings,
        vec!["BLE stop_scan failed: PermissionDenied"]
    );
}

#[tokio::test(start_paused = true)]
async fn scan_warns_when_stop_fails_without_masking_results_or_enumeration_errors() {
    let target = TestDeviceDefinition {
        id: 1,
        discriminator: 0x0abc,
        ..Default::default()
    };
    for list_error in [false, true] {
        let mut state = State {
            stop_error: true,
            list_error,
            ..Default::default()
        };
        state.devices.insert(target.id, target.device());
        let (result, state) = backend::run(state, scan_commissionable(TIMEOUT)).await;
        if list_error {
            assert_eq!(result.err().unwrap().to_string(), "Permission denied");
        } else {
            let found = result.unwrap();
            assert_eq!(found.len(), 1);
            assert_eq!(found[0].discriminator, 0x0abc);
        }
        assert_eq!(
            state.lock().unwrap().warnings,
            vec!["BLE stop_scan failed: PermissionDenied"]
        );
    }
}

#[tokio::test(start_paused = true)]
async fn find_selects_the_matching_definition_among_different_devices() {
    let neighbor = TestDeviceDefinition {
        id: 1,
        discriminator: 0x0247,
        vendor_id: 0x1234,
        product_id: 0x0001,
        advertised_services: vec![MATTER_SERVICE_UUID],
        ..Default::default()
    };
    let target = TestDeviceDefinition {
        id: 2,
        discriminator: 0x0246,
        vendor_id: 0x4321,
        product_id: 0x0002,
        ..Default::default()
    };
    let other = TestDeviceDefinition {
        id: 3,
        discriminator: 0x024a,
        ..target.clone()
    };
    let mut state = State {
        events: vec![
            CentralEvent::DeviceDiscovered(neighbor.id),
            other.advertisement(),
            CentralEvent::DeviceUpdated(target.id),
        ],
        ..Default::default()
    };
    for definition in [&neighbor, &target, &other] {
        state.devices.insert(definition.id, definition.device());
    }
    let (result, state) = backend::run(state, find_by_discriminator(0x0246, false, TIMEOUT)).await;
    finish(result);
    assert_eq!(
        state.lock().unwrap().calls,
        vec![
            Call::Events,
            Call::Start(ScanFilter::default()),
            Call::Lookup(1),
            Call::Properties(1),
            Call::Lookup(2),
            Call::Properties(2),
            Call::Stop,
            Call::Connect(2),
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn find_uses_advertisement_data_independently_of_cached_properties() {
    let cached = TestDeviceDefinition {
        id: 7,
        discriminator: 0x0111,
        ..Default::default()
    };
    let advertised = TestDeviceDefinition {
        discriminator: 0x0abc,
        ..cached.clone()
    };
    let mut state = State {
        events: vec![advertised.advertisement()],
        ..Default::default()
    };
    state.devices.insert(cached.id, cached.device());

    let (result, state) = backend::run(state, find_by_discriminator(0x0abc, false, TIMEOUT)).await;
    finish(result);
    assert_eq!(
        state.lock().unwrap().calls,
        vec![
            Call::Events,
            Call::Start(ScanFilter::default()),
            Call::Lookup(7),
            Call::Stop,
            Call::Connect(7),
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn scan_returns_metadata_for_multiple_device_definitions() {
    let definitions = [
        TestDeviceDefinition {
            id: 9,
            discriminator: 0x0abc,
            advertisement_version: 2,
            vendor_id: 0x1234,
            product_id: 0x5678,
            additional_flags: 0x03,
            name: Some("Service-data-only fixture".to_owned()),
            rssi: Some(-60),
            tx_power: Some(-4),
            ..Default::default()
        },
        TestDeviceDefinition {
            id: 4,
            discriminator: 0x0560,
            vendor_id: 0x4321,
            product_id: 0x00ff,
            advertised_services: vec![MATTER_SERVICE_UUID],
            ..Default::default()
        },
    ];
    // Anchor fixture encoding independently: bit 12..15 is the advertisement version,
    // not a commissioning flag. Flags occupy the final byte.
    assert_eq!(
        definitions[0].service_data(),
        [0x00, 0xbc, 0x2a, 0x34, 0x12, 0x78, 0x56, 0x03]
    );
    assert_eq!(
        definitions[1].service_data(),
        [0x00, 0x60, 0x05, 0x21, 0x43, 0xff, 0x00, 0x00]
    );
    let mut state = State::default();
    for definition in &definitions {
        state.devices.insert(definition.id, definition.device());
    }
    let (result, state) = backend::run(state, scan_commissionable(TIMEOUT)).await;
    let found = result.unwrap();
    assert_eq!(found.len(), definitions.len());
    for definition in &definitions {
        let actual = found
            .iter()
            .find(|device| device.peripheral.id() == definition.id)
            .unwrap();
        assert_eq!(actual.discriminator, definition.discriminator);
        assert_eq!(actual.vendor_id, definition.vendor_id);
        assert_eq!(actual.product_id, definition.product_id);
        assert_eq!(actual.name, definition.name);
        assert_eq!(actual.rssi, definition.rssi);
        assert_eq!(actual.tx_power, definition.tx_power);
        assert_eq!(actual.address, definition.id.to_string());
    }
    assert_eq!(
        state.lock().unwrap().calls,
        vec![
            Call::Start(ScanFilter::default()),
            Call::Stop,
            Call::List,
            Call::Properties(4),
            Call::Properties(9),
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn scan_reads_metadata_from_fixed_wire_vectors() {
    let cases = [
        (MATTER_SERVICE_DATA_ABC, 0x0abc),
        (MATTER_SERVICE_DATA_560, 0x0560),
    ];
    let mut state = State::default();
    for (id, (data, _)) in cases.iter().enumerate() {
        state.devices.insert(id as u64, raw_device(data));
    }
    let (result, _) = backend::run(state, scan_commissionable(TIMEOUT)).await;
    let found = result.unwrap();
    assert_eq!(found.len(), cases.len());
    for (actual, (_, discriminator)) in found.iter().zip(cases) {
        assert_eq!(actual.discriminator, discriminator);
        assert_eq!(actual.vendor_id, 0x132f);
        assert_eq!(actual.product_id, 0x020d);
    }
}
