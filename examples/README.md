# Matter Examples

This directory contains example applications demonstrating how to use the `matc` library, both for
controlling Matter devices (controller side) and for acting as a Matter device (device side).

## Controller examples

### [`devman_demo.rs`](devman_demo.rs) - Device Manager CLI

A feature-rich CLI built on top of `DeviceManager` - the high-level API that handles certificates, discovery, and a persistent device registry automatically.

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

### [`demo.rs`](demo.rs) - Low-level Command Line Tool

A CLI application that exposes the low-level controller library directly. Prefer `devman_demo`
for the higher-level API; use `demo` when you need fine-grained control.

**Features:**
- Device commissioning with PIN codes
- Certificate management (CA bootstrap, controller certificates)
- Device discovery (commissionable and commissioned devices)
- Cluster and attribute operations
- Few example command invocation (On/Off, Level Control, Color Control, etc.)
- Manual pairing code decoding

**Usage:**

Compile with `cargo build --example demo`; the binary is usually at `target/debug/examples/demo`.
It uses clap, so run `--help` to list all supported parameters.

```bash
# Create CA certificates in directory pem:
./demo ca-bootstrap

# Create key/certificate for controller with id 100:
./demo ca-create-controller 100

# Discover all commissionable devices using mdns:
./demo discover commissionable --timeout 3

# Discover all commissioned devices using mdns:
./demo discover commissioned --timeout 3

# Discover a specific device commissioned by us (filters by device-id and our fabric):
./demo discover commissioned2 --timeout 3 --device-id 300

# Extract the passcode from a manual pairing code:
./demo decode-manual-pairing-code 1577-384-0075

# Commission a device (ip 192.168.5.70, passcode 123456, device id 300, admin id 100):
./demo commission 192.168.5.70:5540 100 300 123456

# Update the fabric label on a device:
./demo command invoke-command-update-fabric-label --device-address 192.168.5.70:5540 --controller-id 100 --device-id 300 "testfabric"

# Read any attribute (here attribute 1 / fabrics from cluster 62 / operational credentials on endpoint 0):
./demo command read --device-address 192.168.5.70:5540 --controller-id 100 --device-id 300 0 62 1

# List all attributes in all clusters for all endpoints supported by the device:
./demo command list-attributes --device-address 192.168.5.70:5540 --controller-id 100 --device-id 300

# Turn a device on / off:
./demo command invoke-command-on --device-address 192.168.5.70:5540 --controller-id 100 --device-id 300
./demo command invoke-command-off --device-address 192.168.5.70:5540 --controller-id 100 --device-id 300
```

To start from scratch, remove the `pem` directory.

**Global flags:**
- `--verbose` - enable verbose logs
- `--local-address` - local bind address (ip:port) used as the source for matter UDP requests.
  Default is `0.0.0.0:5555`. For IPv6 set it to e.g. `--local-address "[::]:5555"`.
- `--cert-path` - directory where pem files with keys and certificates are stored


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


### [`simple-ble.rs`](simple-ble.rs) - BLE Commissioning

Commissions a Wi-Fi Matter device that is advertising over BLE, provisions Wi-Fi credentials,
and toggles the On/Off cluster to verify the connection. Requires the `ble` feature.

The full BLE flow is: BLE scan -> BTP PASE -> AddNOC -> NetworkCommissioning (Wi-Fi or Thread
credentials) -> drop BLE -> operational mDNS -> UDP CASE -> CommissioningComplete.

```bash
cargo run --features ble --example simple-ble -- \
  --pairing-code "MT:Y.K908..." --ssid HomeWifi --password secret --node-id 300 --name "kitchen light"
```

For the higher-level API, `devman_demo`'s `commission-ble` / `commission-ble-thread` subcommands
do the same thing.


### [`simple-devman.rs`](simple-devman.rs) - Minimal Device Manager Usage

The shortest path to using the high-level `DeviceManager` API from code: load or create a manager,
commission a device, and read its descriptor. Uses hardcoded values for simplicity.


### [`color.rs`](color.rs) - Color Control CLI

Command-line interface for controlling color-capable devices (e.g. smart LED bulbs) via the
Color Control cluster.

```bash
# Move to a specific hue
cargo run --example color -- --device-address 192.168.1.100:5540 move-to-hue 120 shortest 10

# Set color temperature
cargo run --example color -- --device-address 192.168.1.100:5540 move-to-color-temperature 250 10
```


### [`shell.rs`](shell.rs) - Interactive Controller Shell

A long-running REPL that keeps device connections alive between commands, so after the initial
CASE authentication every subsequent command is dispatched instantly.
This is example for long-running controllers. Demonstrates event/attribute subscriptions.

```bash
# First-time setup
cargo run --example shell -- --data-dir ./matter-data init

# Start the shell (loads an existing device manager)
cargo run --example shell -- --data-dir ./matter-data
```

Type `help` at the prompt for the list of commands.


### [`discover.rs`](discover.rs) - Continuous discovery of Matter devices

Utility which discovers all matter devices using mdns and prints basic info.


## Device-side examples

### [`device.rs`](device.rs) - On/Off Light Device

Runs `matc` as a commissionable Matter device: an On/Off light with a custom `AppHandler`,
multiple endpoints, and state persistence. Use a controller (e.g. `devman_demo` or another Matter
ecosystem) to commission and control it.


### [`device-pki.rs`](device-pki.rs) - Device PKI / Certificate Setup

CLI for generating the device attestation PKI (PAA-style CA, DAC/PAI certificates) used by the
device-side examples.

```bash
cargo run --example device-pki -- --help
```


## Utilities

### [`mdns_send.rs`](mdns_send.rs) - mDNS Packet Sender

Low-level debugging helper that sends a raw mDNS response packet supplied as a hex string.

```bash
cargo run --example mdns_send -- <hex_packet>
```


## Running Examples

```bash
# Show help for cli demo
cargo run --example demo -- --help

# 1. Commission a device and test basic operations
cargo run --example simple

# 2. Run advanced operations on the commissioned device
cargo run --example simple2
```

