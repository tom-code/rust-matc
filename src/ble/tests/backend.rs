//! Test-only platform facade for exercising the public BLE functions without hardware.
//! Advertising properties, scan filters and GATT descriptors use the real btleplug types.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, Once},
};

use btleplug::{
    api::{
        CharPropFlags, Characteristic, PeripheralProperties, ScanFilter, ValueNotification,
        WriteType,
    },
    Error, Result,
};
use futures::{stream, Stream, StreamExt};
use uuid::Uuid;

use super::super::{C1_UUID, C2_UUID, MATTER_SERVICE_UUID};

#[derive(Debug)]
pub enum CentralEvent {
    DeviceDiscovered(u64),
    DeviceUpdated(u64),
    ServiceDataAdvertisement {
        id: u64,
        service_data: HashMap<Uuid, Vec<u8>>,
    },
    Other,
}

#[derive(Debug, PartialEq)]
pub enum Call {
    Events,
    Start(ScanFilter),
    Stop,
    List,
    Lookup(u64),
    Properties(u64),
    Connect(u64),
}

#[derive(Debug, Default)]
pub struct Device {
    pub properties: Option<PeripheralProperties>,
    pub lookup_failures: usize,
    pub properties_failures: usize,
    pub connect_error: bool,
}

#[derive(Debug, Default)]
pub struct State {
    pub events: Vec<CentralEvent>,
    pub devices: BTreeMap<u64, Device>,
    pub calls: Vec<Call>,
    pub end_events: bool,
    pub start_error: bool,
    pub events_error: bool,
    pub list_error: bool,
    pub stop_error: bool,
    pub warnings: Vec<String>,
}

tokio::task_local! {
    static CURRENT: Arc<Mutex<State>>;
}

struct TestLogger;

impl log::Log for TestLogger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.level() <= log::Level::Warn
    }

    fn log(&self, record: &log::Record<'_>) {
        if self.enabled(record.metadata()) {
            // Each test captures only logs from its own task-local scenario.
            let _ = CURRENT.try_with(|state| {
                state
                    .lock()
                    .unwrap()
                    .warnings
                    .push(record.args().to_string());
            });
        }
    }

    fn flush(&self) {}
}

pub async fn run<F: Future>(state: State, future: F) -> (F::Output, Arc<Mutex<State>>) {
    static INIT_LOGGER: Once = Once::new();
    INIT_LOGGER.call_once(|| {
        log::set_logger(&TestLogger).unwrap();
        log::set_max_level(log::LevelFilter::Warn);
    });
    let state = Arc::new(Mutex::new(state));
    let output = CURRENT.scope(state.clone(), future).await;
    (output, state)
}

pub struct Manager(Arc<Mutex<State>>);

impl Manager {
    pub async fn new() -> Result<Self> {
        Ok(Self(CURRENT.with(Arc::clone)))
    }

    pub async fn adapters(&self) -> Result<Vec<Adapter>> {
        Ok(vec![Adapter(self.0.clone())])
    }
}

pub struct Adapter(Arc<Mutex<State>>);

impl Adapter {
    pub async fn events(&self) -> Result<Pin<Box<dyn Stream<Item = CentralEvent> + Send>>> {
        let mut state = self.0.lock().unwrap();
        state.calls.push(Call::Events);
        if state.events_error {
            return Err(Error::PermissionDenied);
        }
        let events = stream::iter(std::mem::take(&mut state.events));
        if state.end_events {
            Ok(Box::pin(events))
        } else {
            Ok(Box::pin(events.chain(stream::pending())))
        }
    }

    pub async fn start_scan(&self, filter: ScanFilter) -> Result<()> {
        let mut state = self.0.lock().unwrap();
        state.calls.push(Call::Start(filter));
        if state.start_error {
            return Err(Error::PermissionDenied);
        }
        Ok(())
    }

    pub async fn stop_scan(&self) -> Result<()> {
        let mut state = self.0.lock().unwrap();
        state.calls.push(Call::Stop);
        if state.stop_error {
            return Err(Error::PermissionDenied);
        }
        Ok(())
    }

    pub async fn peripheral(&self, id: &u64) -> Result<Peripheral> {
        let mut state = self.0.lock().unwrap();
        state.calls.push(Call::Lookup(*id));
        let device = state.devices.get_mut(id).ok_or(Error::DeviceNotFound)?;
        if device.lookup_failures > 0 {
            device.lookup_failures -= 1;
            return Err(Error::DeviceNotFound);
        }
        Ok(Peripheral {
            id: *id,
            state: self.0.clone(),
        })
    }

    pub async fn peripherals(&self) -> Result<Vec<Peripheral>> {
        let mut state = self.0.lock().unwrap();
        state.calls.push(Call::List);
        if state.list_error {
            return Err(Error::PermissionDenied);
        }
        Ok(state
            .devices
            .keys()
            .map(|id| Peripheral {
                id: *id,
                state: self.0.clone(),
            })
            .collect())
    }
}

#[derive(Clone, Debug)]
pub struct Peripheral {
    id: u64,
    state: Arc<Mutex<State>>,
}

impl Peripheral {
    pub fn id(&self) -> u64 {
        self.id
    }

    pub async fn properties(&self) -> Result<Option<PeripheralProperties>> {
        let mut state = self.state.lock().unwrap();
        state.calls.push(Call::Properties(self.id));
        let device = state
            .devices
            .get_mut(&self.id)
            .ok_or(Error::DeviceNotFound)?;
        if device.properties_failures > 0 {
            device.properties_failures -= 1;
            return Err(Error::DeviceNotFound);
        }
        Ok(device.properties.clone())
    }

    pub async fn connect(&self) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        state.calls.push(Call::Connect(self.id));
        if state.devices[&self.id].connect_error {
            return Err(Error::NotConnected);
        }
        Ok(())
    }

    pub async fn discover_services(&self) -> Result<()> {
        Ok(())
    }

    pub fn characteristics(&self) -> BTreeSet<Characteristic> {
        [C1_UUID, C2_UUID]
            .into_iter()
            .map(|uuid| Characteristic {
                uuid,
                service_uuid: MATTER_SERVICE_UUID,
                properties: CharPropFlags::WRITE | CharPropFlags::INDICATE,
                descriptors: BTreeSet::new(),
            })
            .collect()
    }

    pub async fn notifications(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = ValueNotification> + Send>>> {
        Ok(Box::pin(stream::pending()))
    }

    pub async fn write(&self, _: &Characteristic, _: &[u8], _: WriteType) -> Result<()> {
        panic!("discovery must not send GATT data")
    }

    pub async fn subscribe(&self, _: &Characteristic) -> Result<()> {
        panic!("discovery must not subscribe before the BTP handshake")
    }

    pub async fn disconnect(&self) -> Result<()> {
        Ok(())
    }
}
