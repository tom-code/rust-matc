//! Matter controller library
//!
//! This library allows to controll Matter compatible devices. Library uses asynchronous Rust and depends on Tokio.
//! Following are main parts of api:
//! - [Transport](transport::Transport) - Representation of IP/UDP transport. Binds to specified IP/port,
//!                             allows to define virtual connections for remote destinations
//!                             and demultiplexes incoming messages based on these connections.
//! - [CertManager](certmanager::CertManager) - Trait allowing to supply external certificate storage.
//!                                Default implementation [certmanager::FileCertManager] stores certificates to specified directory in PEM format.
//! - [Controller](controller::Controller) - Matter controller - uses [Transport](transport::Transport) to send/receive messages,
//!                              [CertManager](certmanager::CertManager) to get certificates.
//!                              Allows to [commission](controller::Controller::commission) device, [authenticate](controller::Controller::auth_sigma)
//!                              commissioned device. Authenticated device is represented by [Connection](controller::Connection) which allows to
//!                              [read attributes](controller::Connection::read_request) and [invoke commands](controller::Connection::invoke_request).
//! - [tlv](tlv) - Module with simple matter tlv encoders and decoders which can be used to encode command parameters
//!                and decode complex responses.
//! - [im](im) - Typed Interaction Model report layer - decoded attribute/event reports used by
//!              [Connection::read_request2](controller::Connection::read_request2) and the subscription API
//!              ([Connection::subscribe_attrs](controller::Connection::subscribe_attrs) returns a
//!              [Subscription](controller::Subscription) delivering decoded updates).
//! - [discover](discover) - simple mdns based discovery of matter devices on local network
//! - [devman](devman) - High level device manager which uses all above components to provide simpler api.
//!                      It stores device information and certificates in specified directory and allows
//!                      to commission new devices (by address, by manual pairing code with mDNS discovery,
//!                      or over BLE with Wi-Fi/Thread credential provisioning - requires `ble` feature)
//!                      and connect to already commissioned devices by name.
//!                      Connections automatically re-discover devices via operational mDNS if the stored
//!                      address is stale (e.g. device changed IP).
//! - [clusters](clusters) - matter cluster definitions and encoders/decoders for cluster attributes and commands.
//!
//!
//! Examples directory contains simple demo application and simple standalone examples on how to use APIs.
//!
//! Library can be used through high level device manager api or through lower level controller and transport apis.
//! Device manager api is simpler to use, but does not provide same flexibility like lower level apis.
//! For example how to use device manager see simple-devman.rs and devman_demo.rs examples in examples directory.
//!
//! Example how to initialize device manager
//! ```no_run
//! # use matc::devman::DeviceManager;
//! # use anyhow::Result;
//! # use matc::devman::ManagerConfig;
//! # #[tokio::main]
//! # async fn main() -> Result<()> {
//! const FABRIC_ID: u64 = 100;
//! const CONTROLLER_ID: u64 = 200;
//! const LOCAL_ADDRESS: &str = "0.0.0.0:5555";
//! const DATA_DIR: &str = "./matter-data";
//! let config = ManagerConfig {
//!             fabric_id: FABRIC_ID,
//!             controller_id: CONTROLLER_ID,
//!             local_address: LOCAL_ADDRESS.to_string(),
//! };
//! let devman = DeviceManager::create(DATA_DIR, config).await?;
//! # Ok(())
//! # }
//! ```
//!
//! Example how to load existing device manager configuration and commission device using it.
//! Shows both ways to talk to the device - typed facade (recommended) and raw API:
//! ```no_run
//! # use matc::devman::DeviceManager;
//! # use anyhow::Result;
//! # use matc::devman::ManagerConfig;
//! # use matc::clusters;
//! # use matc::clusters::codec::on_off;
//! # #[tokio::main]
//! # async fn main() -> Result<()> {
//! const CONTROLLER_ID: u64 = 200;
//! const NODE_ID: u64 = 300;
//! const NAME: &str = "My Device";
//! const DATA_DIR: &str = "./matter-data";
//! const PIN: u32 = 123456;
//! let devman = DeviceManager::load(DATA_DIR).await?;
//! let device = devman.commission("1.1.1.1:5540", PIN, NODE_ID, NAME).await?;
//!
//! // Option A - typed facade: one call per command / attribute, typed args and return value.
//! on_off::on(&device, 1).await?;
//! let state: bool = on_off::read_on_off(&device, 1).await?;
//!
//! // Option B - raw API: cluster/command IDs + raw TLV payload. Useful when the cluster
//! // is not covered by the facade or when the payload is built dynamically at runtime.
//! device.invoke_request(1, clusters::defs::CLUSTER_ID_ON_OFF, clusters::defs::CLUSTER_ON_OFF_CMD_ID_ON, &[]).await?;
//! # let _ = state;
//! # Ok(())
//! # }
//! ```
//!
//! Example how to commission device using manual pairing code (mDNS discovery happens automatically):
//! ```no_run
//! # use matc::devman::DeviceManager;
//! # use anyhow::Result;
//! # #[tokio::main]
//! # async fn main() -> Result<()> {
//! const DATA_DIR: &str = "./matter-data";
//! let devman = DeviceManager::load(DATA_DIR).await?;
//! let device = devman.commission_with_code("0251-520-0076", 300, "My Device").await?;
//! # Ok(())
//! # }
//! ```
//!
//! Example how to commission a Wi-Fi device that advertises over BLE (requires `ble` feature):
//! ```no_run
//! # #[cfg(feature = "ble")]
//! # {
//! # use matc::devman::DeviceManager;
//! # use anyhow::Result;
//! # use matc::NetworkCreds;
//! # #[tokio::main]
//! # async fn main() -> Result<()> {
//! const DATA_DIR: &str = "./matter-data";
//! let devman = DeviceManager::load(DATA_DIR).await?;
//! let device = devman.commission_ble_with_code(
//!     "MT:Y.K908...",   // QR or manual pairing code
//!     300,              // node ID to assign
//!     "kitchen light",  // friendly name
//!     NetworkCreds::WiFi {
//!         ssid: b"HomeWifi".to_vec(),
//!         creds: b"secret".to_vec(),
//!     },
//! ).await?;
//! # Ok(())
//! # }
//! # }
//! ```
//!
//! Example how to connect to already commissioned device by name and send command to it.
//! If the device changed its IP, the connection automatically re-discovers it via operational mDNS:
//! ```no_run
//! # use matc::devman::DeviceManager;
//! # use anyhow::Result;
//! # use matc::devman::ManagerConfig;
//! # use matc::clusters;
//! # #[tokio::main]
//! # async fn main() -> Result<()> {
//! const DATA_DIR: &str = "./matter-data";
//! const NAME: &str = "My Device";
//! let devman = DeviceManager::load(DATA_DIR).await?;
//! let device = devman.connect_by_name(NAME).await?;
//! device.invoke_request(1, clusters::defs::CLUSTER_ID_ON_OFF, clusters::defs::CLUSTER_ON_OFF_CMD_ID_ON, &[]).await?;
//! # Ok(())
//! # }
//! ```
//!
//! Following are examples how to use lower level APIs without device manager.
//!
//! Example how to initialize certificate authority and create controller user - stores certificates in pem directory:
//! ```no_run
//! # use matc::certmanager::FileCertManager;
//! # use anyhow::Result;
//! # fn main() -> Result<()> {
//! let fabric_id = 1000;
//! let controller_id = 100;
//! let cm = FileCertManager::new(fabric_id, "./pem");
//! cm.bootstrap()?;
//! cm.create_user(controller_id)?;
//! # Ok(())
//! # }
//! ```
//!
//! Example how to commission device using certificates pre-created in pem directory:
//! ```no_run
//! # use matc::certmanager;
//! # use anyhow::Result;
//! # use std::sync::Arc;
//! # use matc::transport;
//! # use matc::controller;
//! # use matc::clusters;
//! # #[tokio::main]
//! # async fn main() -> Result<()> {
//! let fabric_id = 1000;
//! let device_id = 300;
//! let controller_id = 100;
//! let pin = 123456;
//! let cm: Arc<dyn certmanager::CertManager> = certmanager::FileCertManager::load("./pem")?;
//! let transport = transport::Transport::new("0.0.0.0:5555").await?;
//! let controller = controller::Controller::new(&cm, &transport, fabric_id)?;
//! let connection = transport.create_connection("1.2.3.4:5540").await;
//! let mut connection = controller.commission(&connection, pin, device_id, controller_id).await?;
//! // commission method returns authenticated connection which can be used to send commands
//! // now we can send ON command:
//! connection.invoke_request(1,  // endpoint
//!                           clusters::defs::CLUSTER_ID_ON_OFF,
//!                           clusters::defs::CLUSTER_ON_OFF_CMD_ID_ON,
//!                           &[]).await?;
//! # Ok(())
//! # }
//! ```
//!
//! Example sending ON command to device which is already commissioned using certificates pre-created in pem directory:
//! ```no_run
//! # use matc::certmanager;
//! # use anyhow::Result;
//! # use std::sync::Arc;
//! # use matc::transport;
//! # use matc::controller;
//! # use matc::tlv;
//! # use matc::clusters;
//! # #[tokio::main]
//! # async fn main() -> Result<()> {
//! let fabric_id = 1000;
//! let device_id = 300;
//! let controller_id = 100;
//! let cm: Arc<dyn certmanager::CertManager> = certmanager::FileCertManager::load("./pem")?;
//! let transport = transport::Transport::new("0.0.0.0:5555").await?;
//! let controller = controller::Controller::new(&cm, &transport, fabric_id)?;
//! let connection = transport.create_connection("1.2.3.4:5540").await;
//! let mut c = controller.auth_sigma(&connection, device_id, controller_id).await?;
//! // send ON command
//! c.invoke_request(1, // endpoint
//!                  clusters::defs::CLUSTER_ID_ON_OFF,
//!                  clusters::defs::CLUSTER_ON_OFF_CMD_ID_ON,
//!                  &[]).await?;
//! //
//! // invoke SetLevel command to show how to supply command parameters
//! let tlv = tlv::TlvItemEnc {
//!   tag: 0,
//!   value: tlv::TlvItemValueEnc::StructInvisible(vec![
//!     tlv::TlvItemEnc { tag: 0, value: tlv::TlvItemValueEnc::UInt8(50)   }, // level
//!     tlv::TlvItemEnc { tag: 1, value: tlv::TlvItemValueEnc::UInt16(1000)}, // transition time
//!     tlv::TlvItemEnc { tag: 2, value: tlv::TlvItemValueEnc::UInt8(0)    }, // options mask
//!     tlv::TlvItemEnc { tag: 3, value: tlv::TlvItemValueEnc::UInt8(0)    }, // options override
//!   ])
//! }.encode()?;
//! c.invoke_request(1, // endpoint
//!                  clusters::defs::CLUSTER_ID_LEVEL_CONTROL,
//!                  clusters::defs::CLUSTER_LEVEL_CONTROL_CMD_ID_MOVETOLEVEL,
//!                  &tlv).await?;
//! //
//! // read level
//! let result = c.read_request2(1,
//!                              clusters::defs::CLUSTER_ID_LEVEL_CONTROL,
//!                              clusters::defs::CLUSTER_LEVEL_CONTROL_ATTR_ID_CURRENTLEVEL,
//!                              ).await?;
//! println!("{:?}", result);
//! # Ok(())
//! # }
//! ```
//!
//! ## Cluster access: typed facade vs. raw API
//!
//! The examples above use a mix of two styles for talking to a cluster on a connected
//! device. Both are supported and can be mixed freely on the same `Connection`:
//!
//! 1. **Typed facade (recommended for known clusters)** - each generated cluster module in
//!    [clusters::codec] exposes one `pub async fn` per command and one `read_<attr>` per
//!    attribute. Calls take `&Connection, endpoint, ...args` and do encode+invoke+decode
//!    (or read+decode) in a single step, with typed parameters and typed return values
//!    (`Result<()>` for ACK-only commands, `Result<FooResponse>` for commands with a
//!    response struct, the decoder's native Rust type for attributes). See
//!    `examples/simple.rs` for a minimal end-to-end usage.
//!
//!    ```ignore
//!    use matc::clusters::codec::on_off;
//!    on_off::on(&conn, 1).await?;
//!    let state: bool = on_off::read_on_off(&conn, 1).await?;
//!    ```
//!
//! 2. **Raw API (for dynamic / untyped / debugging use)** - the facade is an *alternative*,
//!    not a replacement. The lower-level
//!    [Connection::invoke_request](controller::Connection::invoke_request) /
//!    [Connection::read_request2](controller::Connection::read_request2) methods take
//!    cluster/command/attribute IDs from [clusters::defs] and raw TLV byte payloads, and
//!    return the raw response TLV. Use this when you need to:
//!    - talk to a cluster or field not covered by the generated facade,
//!    - build command payloads dynamically at runtime (e.g. a generic CLI or REPL - see
//!      `examples/demo.rs` and `examples/shell.rs`),
//!    - inspect the raw response TLV (e.g. `res.tlv.dump(1)` for protocol-level debugging),
//!    - use `invoke_request_timed` and other specialized paths the facade does not wrap.
//!
//!
#![doc = include_str!("../readme.md")]

mod active_connection;
#[cfg(feature = "ble")]
pub mod ble;
#[cfg(feature = "ble")]
pub mod btp;
pub mod cert_matter;
pub mod cert_x509;
pub mod certmanager;
pub mod clusters;
mod commission;
pub use commission::NetworkCreds;
pub mod controller;
pub mod device;
mod device_messages;
pub mod devman;
pub mod discover;
pub mod fabric;
pub mod im;
pub mod mdns;
pub mod mdns2;
pub mod messages;
pub mod mrp;
pub mod onboarding;
mod retransmit;
mod session;
mod sigma;
pub mod spake2p;
pub mod tlv;
pub mod transport;
pub mod util;
