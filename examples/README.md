# Matter Controller Examples

This directory contains example applications demonstrating how to use the `matc` (Matter Controller) library for commissioning and controlling Matter devices.

## Examples Overview

### [`devman_demo.rs`](devman_demo.rs) - Device Manager CLI

A feature-rich CLI built on top of `DeviceManager` — the high-level API that handles certificates, discovery, and a persistent device registry automatically.

**Subcommands:**

| Subcommand | Description |
|---|---|
| `init` | First-time setup: creates CA, controller certificate, and config |
| `commission <addr> <node_id> <pin> <name>` | Commission a device at a known IP:port |
| `commission-with-discovery <code> <node_id> <name>` | Commission using manual pairing code + mDNS auto-discovery |
| `commission-ble <code> <node_id> <name> <ssid> [--password]` | Commission a Wi-Fi device over BLE *(requires `--features ble`)* |
| `commission-ble-thread <code> <node_id> <name> <dataset_hex>` | Commission a Thread device over BLE *(requires `--features ble`)* |
| `list` | List all registered devices |
| `on/off/toggle <device>` | Send On/Off cluster commands (device by name or node ID) |
| `remove <device>` | Remove a device from the registry |
| `rename <device> <new_name>` | Rename a device |

**Example workflow:**
```bash
# 1. Initialize
cargo run --example devman_demo -- init ./matter-data --fabric-id 1000 --controller-id 100

# 2a. Commission by address
cargo run --example devman_demo -- -d ./matter-data commission 192.168.1.100:5540 300 123456 "kitchen light"

# 2b. Commission with mDNS discovery
cargo run --example devman_demo -- -d ./matter-data commission-with-discovery "0251-520-0076" 300 "kitchen light"

# 2c. Commission over BLE (Wi-Fi provisioning)
cargo run --features ble --example devman_demo -- -d ./matter-data commission-ble \
  "MT:Y.K908..." 300 "kitchen light" HomeWifi --password "secret"

# 2d. Commission over BLE (Thread provisioning, dataset from `ot-ctl dataset active -x`)
cargo run --features ble --example devman_demo -- -d ./matter-data commission-ble-thread \
  "MT:Y.K908..." 300 "kitchen sensor" 0e080000000000010000...

# 3. Control
cargo run --example devman_demo -- -d ./matter-data on "kitchen light"
cargo run --example devman_demo -- -d ./matter-data off "kitchen light"
```

---

### [`demo.rs`](demo.rs) - Simple Command Line Tool

A simple CLI application that demonstrates all major features of the Matter controller library.

**Features:**
- Device commissioning with PIN codes
- Certificate management (CA bootstrap, controller certificates)
- Device discovery (commissionable and commissioned devices)
- Cluster and attribute operations
- Few example command invocation (On/Off, Level Control, Color Control, etc.)
- Manual pairing code decoding


### [`simple.rs`](simple.rs) - Basic Commissioning and Control

A straightforward example showing the essential steps to commission a device and perform basic On/Off operations.
For simplicity this example uses hardcoded values.

**What it demonstrates:**
- Certificate setup and management
- Device commissioning process
- Basic command invocation (On/Off)
- Attribute reading

**Prerequisites:**
- Device ready for commissioning
- Device implements On/Off cluster
- No existing certificates (creates fresh setup)


### [`simple2.rs`](simple2.rs) - Post-Commission Operations

Demonstrates operations on an already commissioned device.
For simplicity this example uses hardcoded values.

**What it demonstrates:**
- Connecting to previously commissioned device
- On/Off cluster operations
- Level Control cluster operations
- Manual TLV encoding for complex commands

**Prerequisites:**
- Certificates already exist (created by `simple.rs`)
- Device already commissioned
- Device implements On/Off and Level Control clusters


### [`discover.rs`](discover.rs) - Continuous discovery of Matter devices

Utility which discovers all matter devices using mdns and prints basic info.

## Running Examples

```bash
# Show help for cli demo
cargo run --example demo -- --help

# 1. Commission a device and test basic operations
cargo run --example simple

# 2. Run advanced operations on the commissioned device
cargo run --example simple2
```

