# Matter Controller Examples

This directory contains example applications demonstrating how to use the `matc` (Matter Controller) library for commissioning and controlling Matter devices.

## Examples Overview

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


### ['discover.rs](discover.rs) - Continous discovery of matter devices

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

