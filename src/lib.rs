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
//! - [discover](discover) - simple mdns based discovery of matter devices on local network
//!
//!
//! Examples directory contains simple demo application and simple standalone examples on how to use APIs.
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
//!
#![doc = include_str!("../readme.md")]

pub mod cert_matter;
pub mod cert_x509;
pub mod certmanager;
pub mod clusters;
mod commission;
pub mod controller;
pub mod discover;
mod fabric;
pub mod mdns;
pub mod messages;
pub mod onboarding;
mod retransmit;
mod session;
mod sigma;
pub mod spake2p;
pub mod tlv;
pub mod transport;
mod util;
