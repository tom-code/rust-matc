//! Interactive Matter controller shell.
//!
//! A long-running REPL that keeps device connections alive between commands,
//! so after the initial authentication (CASE/SIGMA) every subsequent command
//! is sent immediately without re-authentication overhead.
//!
//! # Usage
//!
//! First-time setup:
//! ```
//! cargo run --example shell -- --data-dir ./matter-data init
//! ```
//!
//! Start the shell (loads an existing device manager):
//! ```
//! cargo run --example shell -- --data-dir ./matter-data
//! ```
//!
//! Type `help` at the prompt for a list of commands.

use anyhow::Result;
use matc::{
    clusters::{self, defs::*},
    controller::Connection,
    devman::{DeviceManager, ManagerConfig},
    discover,
};
use rustyline::{
    completion::{Completer, Pair},
    error::ReadlineError,
    highlight::Highlighter,
    hint::{Hinter, HistoryHinter},
    history::DefaultHistory,
    validate::Validator,
    Context, Editor, Helper,
};
use std::{borrow::Cow, collections::HashMap, io::Write, sync::{Arc, Mutex}, time::Duration};

const DEFAULT_DATA_DIR: &str = "./matter-data";
const DEFAULT_LOCAL_ADDRESS: &str = "0.0.0.0:5555";
const DISCOVER_TIMEOUT_SECS: u64 = 5;

// ── Rustyline helper (completion + history hints) ─────────────────────────────

const COMMANDS: &[&str] = &[
    "help", "quit", "exit",
    "list", "status",
    "init", "commission", "commission-discover", "commission-ble-wifi", "commission-ble-thread", "discover",
    "connect", "connect-all", "disconnect",
    "on", "off", "toggle", "level", "hue",
    "read", "read-all", "clusters", "parts", "invoke",
    "subscribe", "subscribe-onoff", "subscribe-all", "subscribe-events", "unsubscribe", "subscriptions",
    "rename", "remove",
];

/// Commands whose first argument is a device name/id.
const DEVICE_COMMANDS: &[&str] = &[
    "on", "off", "toggle", "level", "hue",
    "read", "read-all", "clusters", "parts", "invoke",
    "subscribe", "subscribe-onoff", "subscribe-all", "subscribe-events", "unsubscribe",
    "connect", "disconnect", "rename", "remove",
];

struct ShellHelper {
    hinter: HistoryHinter,
    /// Device names kept up to date before each readline call.
    device_names: Arc<Mutex<Vec<String>>>,
}

impl Helper for ShellHelper {}

impl Completer for ShellHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &Context,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        let line_to_cursor = &line[..pos];
        let tokens: Vec<&str> = line_to_cursor.split_whitespace().collect();
        let after_space = line_to_cursor.ends_with(' ');

        // Complete command name (first token, not yet followed by a space)
        if tokens.is_empty() || (tokens.len() == 1 && !after_space) {
            let prefix = tokens.first().copied().unwrap_or("");
            let start = pos - prefix.len();
            let candidates = COMMANDS
                .iter()
                .filter(|c| c.starts_with(prefix))
                .map(|c| Pair { display: c.to_string(), replacement: c.to_string() })
                .collect();
            return Ok((start, candidates));
        }

        // Complete device name (second token for device-taking commands)
        let cmd = tokens[0];
        let completing_second =
            (tokens.len() == 1 && after_space) || (tokens.len() == 2 && !after_space);
        if DEVICE_COMMANDS.contains(&cmd) && completing_second {
            let prefix = if after_space { "" } else { tokens.last().copied().unwrap_or("") };
            let start = pos - prefix.len();
            let names = self.device_names.lock().unwrap();
            let candidates = names
                .iter()
                .filter(|n| n.starts_with(prefix))
                .map(|n| Pair { display: n.clone(), replacement: n.clone() })
                .collect();
            return Ok((start, candidates));
        }

        Ok((pos, vec![]))
    }
}

impl Hinter for ShellHelper {
    type Hint = String;
    fn hint(&self, line: &str, pos: usize, ctx: &Context) -> Option<String> {
        self.hinter.hint(line, pos, ctx)
    }
}

impl Highlighter for ShellHelper {
    fn highlight_hint<'h>(&self, hint: &'h str) -> Cow<'h, str> {
        // Dim the history hint so it's visually distinct from typed text.
        Cow::Owned(format!("\x1b[2m{}\x1b[0m", hint))
    }
}

impl Validator for ShellHelper {}

// ── CLI args (minimal, no clap needed for a shell) ───────────────────────────

struct Args {
    data_dir: String,
    verbose: bool,
    /// If Some, run this one command non-interactively then exit (for scripting)
    run_once: Option<String>,
}

fn parse_args() -> Args {
    let mut data_dir = DEFAULT_DATA_DIR.to_string();
    let mut verbose = false;
    let mut run_once = None;
    let mut iter = std::env::args().skip(1).peekable();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--data-dir" | "-d" => {
                if let Some(v) = iter.next() {
                    data_dir = v;
                }
            }
            "--verbose" | "-v" => verbose = true,
            "--run" | "-r" => {
                if let Some(v) = iter.next() {
                    run_once = Some(v);
                }
            }
            _ => {}
        }
    }
    Args { data_dir, verbose, run_once }
}

// ── Shell state ───────────────────────────────────────────────────────────────

struct SubscriptionEntry {
    endpoint: u16,
    cluster: u32,
    attr: u32,
    /// Human-readable label, e.g. "OnOff/OnOff"
    label: String,
}

struct DeviceSubscriptions {
    /// List of active subscriptions, shared with the background listener.
    entries: Arc<Mutex<Vec<SubscriptionEntry>>>,
    /// Background listener task (one per device).
    handle: tokio::task::JoinHandle<()>,
    /// Set when a wildcard subscribe-all is active. Inner Option = endpoint filter (None = all endpoints).
    wildcard: Option<Option<u16>>,
    /// Each entry is one active subscribe-events call; inner Option = endpoint filter.
    wildcard_events: Vec<Option<u16>>,
}

struct Shell {
    dm: DeviceManager,
    /// node_id → active CASE-authenticated connection
    connections: HashMap<u64, Arc<Connection>>,
    /// node_id → subscription state (entries + listener task)
    subscriptions: HashMap<u64, DeviceSubscriptions>,
}

impl Shell {
    fn new(dm: DeviceManager) -> Self {
        Self { dm, connections: HashMap::new(), subscriptions: HashMap::new() }
    }

    /// Resolve "name or node_id" string → node_id.
    fn resolve_node_id(&self, device: &str) -> Result<u64> {
        if let Ok(id) = device.parse::<u64>() {
            if self.dm.get_device(id)?.is_some() {
                return Ok(id);
            }
        }
        // try hex
        if let Some(hex) = device.strip_prefix("0x").or_else(|| device.strip_prefix("0X")) {
            if let Ok(id) = u64::from_str_radix(hex, 16) {
                if self.dm.get_device(id)?.is_some() {
                    return Ok(id);
                }
            }
        }
        let dev = self.dm.get_device_by_name(device)?
            .ok_or_else(|| anyhow::anyhow!("device '{}' not found", device))?;
        Ok(dev.node_id)
    }

    /// Invoke a command, retrying with a fresh connection on transport error.
    async fn invoke_with_retry(
        &mut self,
        device: &str,
        endpoint: u16,
        cluster: u32,
        command: u32,
        payload: &[u8],
    ) -> Result<()> {
        let node_id = self.resolve_node_id(device)?;

        // Try with cached connection first
        let try1: Result<(), anyhow::Error> = if let Some(conn) = self.connections.get(&node_id) {
            match conn.invoke_request(endpoint, cluster, command, payload).await {
                Ok(_) => return Ok(()),
                Err(e) => Err(e),
            }
        } else {
            Err(anyhow::anyhow!("no connection"))
        };

        // On failure, reconnect and retry
        let _ = try1;
        self.connections.remove(&node_id);
        println!("  reconnecting to {} (node {})…", device, node_id);
        let conn = Arc::new(self.dm.connect(node_id).await?);
        self.connections.insert(node_id, conn);
        let conn = self.connections.get(&node_id).unwrap();
        conn.invoke_request(endpoint, cluster, command, payload).await?;
        Ok(())
    }

    /// Read attribute, retrying with a fresh connection on error.
    async fn read_with_retry(
        &mut self,
        device: &str,
        endpoint: u16,
        cluster: u32,
        attr: u32,
    ) -> Result<matc::tlv::TlvItemValue> {
        let node_id = self.resolve_node_id(device)?;

        let try1 = if let Some(conn) = self.connections.get(&node_id) {
            conn.read_request2(endpoint, cluster, attr).await
        } else {
            Err(anyhow::anyhow!("no connection"))
        };

        if let Ok(v) = try1 { return Ok(v) }

        self.connections.remove(&node_id);
        println!("  reconnecting to {} (node {})…", device, node_id);
        let conn = Arc::new(self.dm.connect(node_id).await?);
        self.connections.insert(node_id, conn);
        let conn = self.connections.get(&node_id).unwrap();
        conn.read_request2(endpoint, cluster, attr).await
    }
}

// ── Command parsing ───────────────────────────────────────────────────────────

/// Split a command line into tokens, respecting double-quoted strings.
fn tokenize(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for ch in line.chars() {
        match ch {
            '"' => in_quotes = !in_quotes,
            ' ' | '\t' if !in_quotes => {
                if !current.is_empty() {
                    tokens.push(current.clone());
                    current.clear();
                }
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

/// Parse a u32 from decimal or 0x-prefixed hex.
fn parse_u32(s: &str) -> Result<u32> {
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Ok(u32::from_str_radix(h, 16)?)
    } else {
        Ok(s.parse::<u32>()?)
    }
}

fn parse_u16(s: &str) -> Result<u16> {
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Ok(u16::from_str_radix(h, 16)?)
    } else {
        Ok(s.parse::<u16>()?)
    }
}

fn parse_u64(s: &str) -> Result<u64> {
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Ok(u64::from_str_radix(h, 16)?)
    } else {
        Ok(s.parse::<u64>()?)
    }
}

// ── Command handlers ──────────────────────────────────────────────────────────

fn print_help() {
    println!(
        r#"
Matter Interactive Shell — available commands:

  Device management:
    list                                  List registered devices
    status                                Show connection status for all devices
    rename <device> <new_name>            Rename a device
    remove <device>                       Remove device from registry

  Commissioning:
    init [--fabric-id N] [--controller-id N] [--local-addr ADDR]
                                          First-time setup (creates CA & controller certs)
    commission <addr> <node_id> <pin> <name>
                                          Commission device at known address
    commission-discover <pairing_code> <node_id> <name>
                                          Commission via mDNS discovery
    commission-ble-wifi <pairing_code> <node_id> <name> <ssid> <password>
                                          Commission via BLE, provision Wi-Fi (requires --features ble)
    commission-ble-thread <pairing_code> <node_id> <name> <dataset_hex>
                                          Commission via BLE, provision Thread (requires --features ble)
    discover [--timeout N]               Discover commissionable devices (default 5s)

  Connection management:
    connect <device>                      Pre-connect (CASE auth) to a device
    connect-all                           Connect to all registered devices
    disconnect <device>                   Drop cached connection

  OnOff cluster:
    on <device> [endpoint]               Turn on (default endpoint 1)
    off <device> [endpoint]              Turn off
    toggle <device> [endpoint]           Toggle

  Level control:
    level <device> <level 0-254> [endpoint]
                                          Set brightness level

  Color control:
    hue <device> <hue 0-254> [endpoint]  Set hue

  Attribute reading:
    read <device> <endpoint> <cluster> <attr>
                                          Read one attribute (hex or decimal IDs)
    read-all <device>                     Read all known attributes on all endpoints
    clusters <device> [endpoint]          List supported clusters on endpoint (default 0)
    parts <device>                        List endpoints (descriptor parts list)

  Subscriptions:
    subscribe <device> <endpoint> <cluster> <attr>
                                          Subscribe to any attribute change
    subscribe-onoff <device> [endpoint]   Shorthand: subscribe to OnOff (default ep 1)
    subscribe-all <device> [endpoint]     Subscribe to all attributes (optionally filtered to one endpoint)
    subscribe-events <device> [endpoint]  Subscribe to all events
    unsubscribe <device>                  Cancel all subscriptions on a device
    subscriptions                         List all active subscriptions

  Generic invoke:
    invoke <device> <endpoint> <cluster> <command> [hex_payload]
                                          Invoke any command with optional TLV payload

  Other:
    help                                  Show this help
    quit / exit                           Exit the shell

  Notes:
    <device> can be a device name or node ID (decimal or 0x hex).
    Cluster/attribute/command IDs accept decimal or 0x-prefixed hex.
"#
    );
}

async fn cmd_init(args: &[String], data_dir: &str) -> Result<()> {
    let mut fabric_id: u64 = 1000;
    let mut controller_id: u64 = 100;
    let mut local_address = DEFAULT_LOCAL_ADDRESS.to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--fabric-id" => {
                i += 1;
                fabric_id = parse_u64(&args[i])?;
            }
            "--controller-id" => {
                i += 1;
                controller_id = parse_u64(&args[i])?;
            }
            "--local-addr" => {
                i += 1;
                local_address = args[i].clone();
            }
            _ => {}
        }
        i += 1;
    }
    let config = ManagerConfig { fabric_id, controller_id, local_address };
    DeviceManager::create(data_dir, config).await?;
    println!("Device manager initialized in '{}'.", data_dir);
    Ok(())
}

async fn cmd_commission(shell: &mut Shell, args: &[String]) -> Result<()> {
    if args.len() < 4 {
        println!("usage: commission <addr> <node_id> <pin> <name>");
        return Ok(());
    }
    let addr = &args[0];
    let node_id = parse_u64(&args[1])?;
    let pin: u32 = args[2].parse()?;
    let name = &args[3];
    println!("Commissioning '{}' (node {}) at {} …", name, node_id, addr);
    let conn = Arc::new(shell.dm.commission(addr, pin, node_id, name).await?);
    println!("Commissioned '{}' (node {}).", name, node_id);

    // Show supported clusters on endpoint 0
    if let Ok(matc::tlv::TlvItemValue::List(l)) = conn
        .read_request2(0, CLUSTER_ID_DESCRIPTOR, CLUSTER_DESCRIPTOR_ATTR_ID_SERVERLIST)
        .await
    {
        println!("Supported clusters on ep0:");
        for item in l {
            if let matc::tlv::TlvItemValue::Int(v) = item.value {
                let cname = clusters::names::get_cluster_name(v as u32)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| format!("0x{:04x}", v));
                println!("  {}", cname);
            }
        }
    }
    shell.connections.insert(node_id, conn);
    Ok(())
}

async fn cmd_commission_discover(shell: &mut Shell, args: &[String]) -> Result<()> {
    if args.len() < 3 {
        println!("usage: commission-discover <pairing_code> <node_id> <name>");
        return Ok(());
    }
    let code = &args[0];
    let node_id = parse_u64(&args[1])?;
    let name = &args[2];
    println!("Discovering and commissioning '{}' (node {}) …", name, node_id);
    let conn = Arc::new(shell.dm.commission_with_code(code, node_id, name).await?);
    println!("Commissioned '{}' (node {}).", name, node_id);
    shell.connections.insert(node_id, conn);
    Ok(())
}

#[cfg(feature = "ble")]
async fn cmd_commission_ble_wifi(shell: &mut Shell, args: &[String]) -> Result<()> {
    if args.len() < 5 {
        println!("usage: commission-ble-wifi <pairing_code> <node_id> <name> <ssid> <password>");
        return Ok(());
    }
    let code = &args[0];
    let node_id = parse_u64(&args[1])?;
    let name = &args[2];
    let ssid = &args[3];
    let password = &args[4];
    println!("Scanning BLE for '{}' (node {}) …", name, node_id);
    let conn = Arc::new(shell.dm.commission_ble_with_code(
        code, node_id, name,
        matc::NetworkCreds::WiFi {
            ssid: ssid.as_bytes().to_vec(),
            creds: password.as_bytes().to_vec(),
        },
    ).await?);
    println!("Commissioned '{}' (node {}).", name, node_id);
    shell.connections.insert(node_id, conn);
    Ok(())
}

#[cfg(not(feature = "ble"))]
async fn cmd_commission_ble_wifi(_shell: &mut Shell, _args: &[String]) -> Result<()> {
    println!("commission-ble-wifi requires building with --features ble");
    Ok(())
}

#[cfg(feature = "ble")]
async fn cmd_commission_ble_thread(shell: &mut Shell, args: &[String]) -> Result<()> {
    if args.len() < 4 {
        println!("usage: commission-ble-thread <pairing_code> <node_id> <name> <dataset_hex>");
        return Ok(());
    }
    let code = &args[0];
    let node_id = parse_u64(&args[1])?;
    let name = &args[2];
    let dataset = hex::decode(&args[3])
        .map_err(|e| anyhow::anyhow!("dataset hex decode: {}", e))?;
    println!("Scanning BLE for '{}' (node {}) …", name, node_id);
    let conn = Arc::new(shell.dm.commission_ble_with_code(
        code, node_id, name,
        matc::NetworkCreds::Thread { dataset },
    ).await?);
    println!("Commissioned '{}' (node {}).", name, node_id);
    shell.connections.insert(node_id, conn);
    Ok(())
}

#[cfg(not(feature = "ble"))]
async fn cmd_commission_ble_thread(_shell: &mut Shell, _args: &[String]) -> Result<()> {
    println!("commission-ble-thread requires building with --features ble");
    Ok(())
}

fn cmd_list(shell: &Shell) -> Result<()> {
    let devices = shell.dm.list_devices()?;
    if devices.is_empty() {
        println!("No devices registered.");
    } else {
        println!("{:<10} {:<8} {:<25} Name", "Node ID", "Status", "Address");
        println!("{}", "─".repeat(62));
        for d in devices {
            let status = if shell.connections.contains_key(&d.node_id) {
                "connected"
            } else {
                "offline"
            };
            println!("{:<10} {:<8} {:<25} {}", d.node_id, status, d.address, d.name);
        }
    }
    Ok(())
}

fn cmd_status(shell: &Shell) -> Result<()> {
    let devices = shell.dm.list_devices()?;
    let total = devices.len();
    let connected = devices.iter().filter(|d| shell.connections.contains_key(&d.node_id)).count();
    println!("{} device(s) registered, {} connected.", total, connected);
    for d in &devices {
        let icon = if shell.connections.contains_key(&d.node_id) { "●" } else { "○" };
        println!("  {} {} (node {}) — {}", icon, d.name, d.node_id, d.address);
    }
    Ok(())
}

async fn cmd_connect(shell: &mut Shell, args: &[String]) -> Result<()> {
    if args.is_empty() {
        println!("usage: connect <device>");
        return Ok(());
    }
    let device = &args[0];
    let node_id = shell.resolve_node_id(device)?;
    if shell.connections.contains_key(&node_id) {
        println!("Already connected to '{}'.", device);
        return Ok(());
    }
    println!("Connecting to '{}' (node {}) …", device, node_id);
    let conn = Arc::new(shell.dm.connect(node_id).await?);
    shell.connections.insert(node_id, conn);
    println!("Connected.");
    Ok(())
}

async fn cmd_connect_all(shell: &mut Shell) -> Result<()> {
    let devices = shell.dm.list_devices()?;
    if devices.is_empty() {
        println!("No devices registered.");
        return Ok(());
    }
    let node_ids: Vec<u64> = devices.iter().map(|d| d.node_id).collect();
    for node_id in node_ids {
        if shell.connections.contains_key(&node_id) {
            continue;
        }
        let dev = shell.dm.get_device(node_id)?.unwrap();
        print!("  Connecting to '{}' (node {}) … ", dev.name, node_id);
        let _ = std::io::stdout().flush();
        match shell.dm.connect(node_id).await {
            Ok(conn) => {
                shell.connections.insert(node_id, Arc::new(conn));
                println!("OK");
            }
            Err(e) => println!("FAILED: {}", e),
        }
    }
    Ok(())
}

fn cmd_disconnect(shell: &mut Shell, args: &[String]) -> Result<()> {
    if args.is_empty() {
        println!("usage: disconnect <device>");
        return Ok(());
    }
    let node_id = shell.resolve_node_id(&args[0])?;
    if let Some(ds) = shell.subscriptions.remove(&node_id) {
        ds.handle.abort();
    }
    if shell.connections.remove(&node_id).is_some() {
        println!("Disconnected (node {}).", node_id);
    } else {
        println!("Not connected (node {}).", node_id);
    }
    Ok(())
}

async fn cmd_on(shell: &mut Shell, args: &[String]) -> Result<()> {
    if args.is_empty() { println!("usage: on <device> [endpoint]"); return Ok(()); }
    let device = &args[0];
    let endpoint: u16 = if args.len() > 1 { parse_u16(&args[1])? } else { 1 };
    shell.invoke_with_retry(device, endpoint, CLUSTER_ID_ON_OFF, CLUSTER_ON_OFF_CMD_ID_ON, &[]).await?;
    println!("ON → '{}'", device);
    Ok(())
}

async fn cmd_off(shell: &mut Shell, args: &[String]) -> Result<()> {
    if args.is_empty() { println!("usage: off <device> [endpoint]"); return Ok(()); }
    let device = &args[0];
    let endpoint: u16 = if args.len() > 1 { parse_u16(&args[1])? } else { 1 };
    shell.invoke_with_retry(device, endpoint, CLUSTER_ID_ON_OFF, CLUSTER_ON_OFF_CMD_ID_OFF, &[]).await?;
    println!("OFF → '{}'", device);
    Ok(())
}

async fn cmd_toggle(shell: &mut Shell, args: &[String]) -> Result<()> {
    if args.is_empty() { println!("usage: toggle <device> [endpoint]"); return Ok(()); }
    let device = &args[0];
    let endpoint: u16 = if args.len() > 1 { parse_u16(&args[1])? } else { 1 };
    shell.invoke_with_retry(device, endpoint, CLUSTER_ID_ON_OFF, CLUSTER_ON_OFF_CMD_ID_TOGGLE, &[]).await?;
    println!("TOGGLE → '{}'", device);
    Ok(())
}

async fn cmd_level(shell: &mut Shell, args: &[String]) -> Result<()> {
    if args.len() < 2 { println!("usage: level <device> <level 0-254> [endpoint]"); return Ok(()); }
    let device = &args[0];
    let level: u8 = args[1].parse()?;
    let endpoint: u16 = if args.len() > 2 { parse_u16(&args[2])? } else { 1 };
    let payload = clusters::codec::level_control::encode_move_to_level(
        level,
        Some(0),
        0,
        0,
    )?;
    shell.invoke_with_retry(
        device, endpoint,
        CLUSTER_ID_LEVEL_CONTROL,
        CLUSTER_LEVEL_CONTROL_CMD_ID_MOVETOLEVEL,
        &payload,
    ).await?;
    println!("LEVEL {} → '{}'", level, device);
    Ok(())
}

async fn cmd_hue(shell: &mut Shell, args: &[String]) -> Result<()> {
    if args.len() < 2 { println!("usage: hue <device> <hue 0-254> [endpoint]"); return Ok(()); }
    let device = &args[0];
    let hue: u8 = args[1].parse()?;
    let endpoint: u16 = if args.len() > 2 { parse_u16(&args[2])? } else { 1 };
    let payload = clusters::codec::color_control::encode_move_to_hue(
        hue,
        clusters::codec::color_control::Direction::Shortest,
        0, 0, 0,
    )?;
    shell.invoke_with_retry(
        device, endpoint,
        CLUSTER_ID_COLOR_CONTROL,
        CLUSTER_COLOR_CONTROL_CMD_ID_MOVETOHUE,
        &payload,
    ).await?;
    println!("HUE {} → '{}'", hue, device);
    Ok(())
}

async fn cmd_read(shell: &mut Shell, args: &[String]) -> Result<()> {
    if args.len() < 4 {
        println!("usage: read <device> <endpoint> <cluster> <attr>");
        return Ok(());
    }
    let device = &args[0];
    let endpoint = parse_u16(&args[1])?;
    let cluster = parse_u32(&args[2])?;
    let attr = parse_u32(&args[3])?;
    let value = shell.read_with_retry(device, endpoint, cluster, attr).await?;
    let json = clusters::codec::decode_attribute_json(cluster, attr, &value);
    let attr_name = clusters::codec::get_attribute_list(cluster)
        .into_iter()
        .find(|(id, _)| *id == attr)
        .map(|(_, name)| name)
        .unwrap_or("?");
    let cluster_name = clusters::names::get_cluster_name(cluster).unwrap_or("?");
    println!(
        "ep{} / {} (0x{:04x}) / {} (0x{:04x}) = {}",
        endpoint, cluster_name, cluster, attr_name, attr, json
    );
    Ok(())
}

async fn cmd_read_all(shell: &mut Shell, args: &[String]) -> Result<()> {
    if args.is_empty() { println!("usage: read-all <device>"); return Ok(()); }
    let device = args[0].clone();
    let node_id = shell.resolve_node_id(&device)?;

    // Ensure connection
    if !shell.connections.contains_key(&node_id) {
        println!("  connecting to '{}' …", device);
        let conn = Arc::new(shell.dm.connect(node_id).await?);
        shell.connections.insert(node_id, conn);
    }

    let conn = shell.connections.get(&node_id).unwrap();

    // Get parts list (endpoints)
    let parts_tlv = conn.read_request2(0, CLUSTER_ID_DESCRIPTOR, CLUSTER_DESCRIPTOR_ATTR_ID_PARTSLIST).await?;
    let mut endpoints: Vec<u16> = match parts_tlv {
        matc::tlv::TlvItemValue::List(items) => items.iter().filter_map(|i| {
            if let matc::tlv::TlvItemValue::Int(v) = i.value { Some(v as u16) } else { None }
        }).collect(),
        _ => vec![],
    };
    endpoints.push(0);
    endpoints.sort();
    endpoints.dedup();

    for ep in endpoints {
        // Get server cluster list for this endpoint
        let cluster_tlv = conn.read_request2(ep, CLUSTER_ID_DESCRIPTOR, CLUSTER_DESCRIPTOR_ATTR_ID_SERVERLIST).await;
        let cluster_list = match cluster_tlv {
            Ok(matc::tlv::TlvItemValue::List(items)) => items.iter().filter_map(|i| {
                if let matc::tlv::TlvItemValue::Int(v) = i.value { Some(v as u32) } else { None }
            }).collect::<Vec<u32>>(),
            _ => continue,
        };

        println!("\n  Endpoint {}:", ep);
        for cluster in cluster_list {
            let attr_list = clusters::codec::get_attribute_list(cluster);
            if attr_list.is_empty() {
                let cname = clusters::names::get_cluster_name(cluster)
                    .unwrap_or("?");
                println!("    [{}] (no decoded attributes)", cname);
                continue;
            }
            let cname = clusters::names::get_cluster_name(cluster).unwrap_or("?");
            println!("    [{}]", cname);
            for (attr_id, attr_name) in attr_list {
                match conn.read_request2(ep, cluster, attr_id).await {
                    Ok(v) => {
                        let json = clusters::codec::decode_attribute_json(cluster, attr_id, &v);
                        println!("      {} = {}", attr_name, json);
                    }
                    Err(e) => println!("      {} = <error: {}>", attr_name, e),
                }
            }
        }
    }
    Ok(())
}

async fn cmd_clusters(shell: &mut Shell, args: &[String]) -> Result<()> {
    if args.is_empty() { println!("usage: clusters <device> [endpoint]"); return Ok(()); }
    let device = &args[0];
    let endpoint: u16 = if args.len() > 1 { parse_u16(&args[1])? } else { 0 };
    let value = shell.read_with_retry(device, endpoint, CLUSTER_ID_DESCRIPTOR, CLUSTER_DESCRIPTOR_ATTR_ID_SERVERLIST).await?;
    println!("Clusters on endpoint {} of '{}':", endpoint, device);
    if let matc::tlv::TlvItemValue::List(items) = value {
        for item in items {
            if let matc::tlv::TlvItemValue::Int(v) = item.value {
                let name = clusters::names::get_cluster_name(v as u32)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "?".to_string());
                println!("  0x{:04x}  {}", v, name);
            }
        }
    }
    Ok(())
}

async fn cmd_parts(shell: &mut Shell, args: &[String]) -> Result<()> {
    if args.is_empty() { println!("usage: parts <device>"); return Ok(()); }
    let device = &args[0];
    let value = shell.read_with_retry(device, 0, CLUSTER_ID_DESCRIPTOR, CLUSTER_DESCRIPTOR_ATTR_ID_PARTSLIST).await?;
    print!("Endpoints on '{}':", device);
    if let matc::tlv::TlvItemValue::List(items) = value {
        for item in items {
            if let matc::tlv::TlvItemValue::Int(v) = item.value {
                print!(" {}", v);
            }
        }
    }
    println!();
    Ok(())
}

async fn cmd_discover(args: &[String]) -> Result<()> {
    let mut timeout = DISCOVER_TIMEOUT_SECS;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--timeout" {
            i += 1;
            if i < args.len() {
                timeout = args[i].parse().unwrap_or(DISCOVER_TIMEOUT_SECS);
            }
        }
        i += 1;
    }
    println!("Discovering commissionable devices for {}s …", timeout);
    let infos = discover::discover_commissionable(Duration::from_secs(timeout)).await?;
    if infos.is_empty() {
        println!("No commissionable devices found.");
    } else {
        println!("Found {} device(s):", infos.len());
        for info in infos {
            let ip_port = info.ips.first()
                .map(|ip| format!("{}:{}", ip, info.port.unwrap_or(5540)))
                .unwrap_or_else(|| "?".to_string());
            println!("  {} — {} (disc: {:?})", ip_port, info.instance,
                     info.discriminator.as_deref().unwrap_or("?"));
        }
    }
    Ok(())
}

async fn cmd_invoke(shell: &mut Shell, args: &[String]) -> Result<()> {
    if args.len() < 4 {
        println!("usage: invoke <device> <endpoint> <cluster> <command> [hex_payload]");
        return Ok(());
    }
    let device = &args[0];
    let endpoint = parse_u16(&args[1])?;
    let cluster = parse_u32(&args[2])?;
    let command = parse_u32(&args[3])?;
    let payload: Vec<u8> = if args.len() > 4 {
        hex::decode(&args[4]).map_err(|e| anyhow::anyhow!("hex decode: {}", e))?
    } else {
        vec![]
    };
    shell.invoke_with_retry(device, endpoint, cluster, command, &payload).await?;
    println!("invoke OK: ep{} cluster=0x{:04x} cmd=0x{:04x}", endpoint, cluster, command);
    Ok(())
}

/// Build a human-readable label for a cluster/attribute pair.
fn attr_label(cluster: u32, attr: u32) -> String {
    let cluster_name = matc::clusters::names::get_cluster_name(cluster).unwrap_or("?");
    let attr_name = matc::clusters::codec::get_attribute_list(cluster)
        .into_iter()
        .find(|(id, _)| *id == attr)
        .map(|(_, name)| name)
        .unwrap_or("?");
    format!("{}/{}", cluster_name, attr_name)
}

fn event_label(cluster: u32, event: u32) -> String {
    let cluster_name = matc::clusters::names::get_cluster_name(cluster).unwrap_or("?");
    format!("{}/0x{:04x}", cluster_name, event)
}

/// Decode all (endpoint, cluster, attr, value) tuples from a ReportData TLV.
/// Iterates the full AttributeReports list so batched reports are not missed.
fn decode_attr_reports(tlv: &matc::tlv::TlvItem) -> Vec<(u16, u32, u32, matc::tlv::TlvItemValue)> {
    let mut out = Vec::new();
    // AttributeReports = tag 1, value = List of AttributeReportIB
    if let Some(attr_reports) = tlv.get_item(&[1]) {
        if let matc::tlv::TlvItemValue::List(reports) = &attr_reports.value {
            for report_ib in reports {
                // Within each AttributeReportIB, navigate AttributeDataIB (tag 1):
                //   tag 1 = AttributePathIB → tag 2=endpoint, 3=cluster, 4=attr
                //   tag 2 = Data value
                let ep  = report_ib.get_u16(&[1, 1, 2]);
                let cl  = report_ib.get_u32(&[1, 1, 3]);
                let att = report_ib.get_u32(&[1, 1, 4]);
                let val = report_ib.get(&[1, 2]).cloned();
                if let (Some(ep), Some(cl), Some(att), Some(val)) = (ep, cl, att, val) {
                    out.push((ep, cl, att, val));
                }
            }
        }
    }
    out
}

/// Decode all (endpoint, cluster, event, event_number, data) tuples from a ReportData TLV.
/// EventReports = tag 2, List of EventReportIB. Within each:
///   EventData (tag 1): Path (tag 0) -> ep=[1,0,1], cluster=[1,0,2], event=[1,0,3];
///   EventNumber=[1,1]; Data=[1,7].
fn decode_event_reports(tlv: &matc::tlv::TlvItem) -> Vec<(u16, u32, u32, u64, matc::tlv::TlvItemValue)> {
    let mut out = Vec::new();
    if let Some(event_reports) = tlv.get_item(&[2]) {
        if let matc::tlv::TlvItemValue::List(reports) = &event_reports.value {
            for report_ib in reports {
                let ep  = report_ib.get_u16(&[1, 0, 1]);
                let cl  = report_ib.get_u32(&[1, 0, 2]);
                let ev  = report_ib.get_u32(&[1, 0, 3]);
                let num = report_ib.get_u64(&[1, 1]);
                let val = report_ib.get(&[1, 7]).cloned();
                if let (Some(ep), Some(cl), Some(ev), Some(num), Some(val)) = (ep, cl, ev, num, val) {
                    out.push((ep, cl, ev, num, val));
                }
            }
        }
    }
    out
}

/// Spawn the background listener task for subscription updates on a device connection.
fn spawn_listener(
    conn: Arc<Connection>,
    device_name: String,
    entries: Arc<Mutex<Vec<SubscriptionEntry>>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let ev = match conn.recv_event().await {
                Some(e) => e,
                None => break,
            };
            match ev.protocol_header.opcode {
                matc::messages::ProtocolMessageHeader::INTERACTION_OPCODE_REPORT_DATA => {
                    for (rep_ep, rep_cl, rep_att, val) in decode_attr_reports(&ev.tlv) {
                        let lbl = {
                            let entries = entries.lock().unwrap();
                            entries.iter()
                                .find(|e| e.endpoint == rep_ep && e.cluster == rep_cl && e.attr == rep_att)
                                .map(|e| e.label.clone())
                                .unwrap_or_else(|| attr_label(rep_cl, rep_att))
                        };
                        let json = matc::clusters::codec::decode_attribute_json(rep_cl, rep_att, &val);
                        println!("[{}] ep{} {} = {}", device_name, rep_ep, lbl, json);
                    }
                    for (rep_ep, rep_cl, rep_ev, num, val) in decode_event_reports(&ev.tlv) {
                        let json = matc::clusters::codec::decode_event_json(rep_cl, rep_ev, &val);
                        println!("[{}] ep{} EVENT {} #{} = {}", device_name, rep_ep, event_label(rep_cl, rep_ev), num, json);
                    }
                    let status_flags =
                        if ev.protocol_header.exchange_flags & matc::messages::ProtocolMessageHeader::FLAG_INITIATOR == 0 {
                            matc::messages::ProtocolMessageHeader::FLAG_INITIATOR | matc::messages::ProtocolMessageHeader::FLAG_ACK
                        } else {
                            matc::messages::ProtocolMessageHeader::FLAG_ACK
                        };
                    let _ = conn.im_status_response(ev.protocol_header.exchange_id, status_flags, ev.message_header.message_counter).await;
                }
                matc::messages::ProtocolMessageHeader::INTERACTION_OPCODE_SUBSCRIBE_RESP => {
                    // periodic heartbeat — ignore
                }
                _ => {
                    log::debug!("[{}] subscription: unhandled opcode 0x{:x}", device_name, ev.protocol_header.opcode);
                }
            }
        }
        log::debug!("[{}] subscription listener exited", device_name);
    })
}

/// Core subscribe logic: subscribe to one attribute, print priming value,
/// start the background listener if not already running, add entry to list.
async fn do_subscribe(
    shell: &mut Shell,
    device: &str,
    endpoint: u16,
    cluster: u32,
    attr: u32,
) -> Result<()> {
    let node_id = shell.resolve_node_id(device)?;

    // Ensure connection
    if !shell.connections.contains_key(&node_id) {
        println!("  connecting to '{}' …", device);
        let conn = Arc::new(shell.dm.connect(node_id).await?);
        shell.connections.insert(node_id, conn);
    }
    let conn = shell.connections.get(&node_id).unwrap().clone();

    // Keep existing subscriptions alive when adding a second one on the same connection.
    let keep = shell.subscriptions.contains_key(&node_id);
    let res = conn.im_subscribe_request_attr(endpoint, cluster, attr, keep).await?;

    if res.protocol_header.opcode != matc::messages::ProtocolMessageHeader::INTERACTION_OPCODE_REPORT_DATA {
        println!("unexpected subscribe response opcode 0x{:x}", res.protocol_header.opcode);
        return Ok(());
    }

    // Print priming report (current state)
    let label = attr_label(cluster, attr);
    let priming = decode_attr_reports(&res.tlv);
    if let Some((_, _, _, val)) = priming.first() {
        let json = matc::clusters::codec::decode_attribute_json(cluster, attr, val);
        println!("[{}] ep{} {} = {} (current)", device, endpoint, label, json);
    } else {
        println!("[{}] ep{} {} subscribed (no initial value)", device, endpoint, label);
    }

    // Ack priming report
    conn.im_status_response(res.protocol_header.exchange_id, 1 | 2, res.message_header.message_counter).await?;

    // Do NOT wait for SubscribeResponse here: if a listener is already running it holds
    // the recv_event lock and we would deadlock. The listener receives and ignores it.

    // If first subscription on this device, start the background listener
    if let std::collections::hash_map::Entry::Vacant(e) = shell.subscriptions.entry(node_id) {
        let entries: Arc<Mutex<Vec<SubscriptionEntry>>> = Arc::new(Mutex::new(Vec::new()));
        let handle = spawn_listener(conn, device.to_string(), entries.clone());
        e.insert(DeviceSubscriptions { entries, handle, wildcard: None, wildcard_events: vec![] });
    }

    // Register the new entry
    let entry = SubscriptionEntry { endpoint, cluster, attr, label: label.clone() };
    shell.subscriptions.get(&node_id).unwrap().entries.lock().unwrap().push(entry);

    println!("Subscribed: [{}] ep{} {}. Use 'unsubscribe {}' to stop.", device, endpoint, label, device);
    Ok(())
}

async fn cmd_subscribe(shell: &mut Shell, args: &[String]) -> Result<()> {
    if args.len() < 4 {
        println!("usage: subscribe <device> <endpoint> <cluster> <attr>");
        return Ok(());
    }
    let device = args[0].clone();
    let endpoint = parse_u16(&args[1])?;
    let cluster = parse_u32(&args[2])?;
    let attr = parse_u32(&args[3])?;
    do_subscribe(shell, &device, endpoint, cluster, attr).await
}

async fn cmd_subscribe_onoff(shell: &mut Shell, args: &[String]) -> Result<()> {
    if args.is_empty() {
        println!("usage: subscribe-onoff <device> [endpoint]");
        return Ok(());
    }
    let device = args[0].clone();
    let endpoint: u16 = if args.len() > 1 { parse_u16(&args[1])? } else { 1 };
    do_subscribe(shell, &device, endpoint, CLUSTER_ID_ON_OFF, CLUSTER_ON_OFF_ATTR_ID_ONOFF).await
}
async fn cmd_subscribe_all(shell: &mut Shell, args: &[String]) -> Result<()> {
    if args.is_empty() {
        println!("usage: subscribe-all <device> [endpoint]");
        return Ok(());
    }
    let device = args[0].clone();
    let endpoint: Option<u16> = if args.len() > 1 { Some(parse_u16(&args[1])?) } else { None };

    let node_id = shell.resolve_node_id(&device)?;
    if !shell.connections.contains_key(&node_id) {
        println!("  connecting to '{}' …", device);
        let conn = Arc::new(shell.dm.connect(node_id).await?);
        shell.connections.insert(node_id, conn);
    }
    let conn = shell.connections.get(&node_id).unwrap().clone();

    let keep = shell.subscriptions.contains_key(&node_id);
    let res = conn.im_subscribe_request_attr2(endpoint, None, None, keep).await?;

    if res.protocol_header.opcode != matc::messages::ProtocolMessageHeader::INTERACTION_OPCODE_REPORT_DATA {
        println!("unexpected subscribe response opcode 0x{:x}", res.protocol_header.opcode);
        return Ok(());
    }

    let priming = decode_attr_reports(&res.tlv);
    if priming.is_empty() {
        println!("[{}] wildcard subscribed (no initial values)", device);
    } else {
        for (ep, cl, att, val) in &priming {
            let json = matc::clusters::codec::decode_attribute_json(*cl, *att, val);
            println!("[{}] ep{} {} = {} (current)", device, ep, attr_label(*cl, *att), json);
        }
    }

    conn.im_status_response(res.protocol_header.exchange_id, 1 | 2, res.message_header.message_counter).await?;

    if let std::collections::hash_map::Entry::Vacant(e) = shell.subscriptions.entry(node_id) {
        let entries: Arc<Mutex<Vec<SubscriptionEntry>>> = Arc::new(Mutex::new(Vec::new()));
        let handle = spawn_listener(conn, device.clone(), entries.clone());
        e.insert(DeviceSubscriptions { entries, handle, wildcard: Some(endpoint), wildcard_events: vec![] });
    } else {
        shell.subscriptions.get_mut(&node_id).unwrap().wildcard = Some(endpoint);
    }

    match endpoint {
        Some(ep) => println!("Subscribed (wildcard ep{}): [{}]. Use 'unsubscribe {}' to stop.", ep, device, device),
        None     => println!("Subscribed (wildcard all): [{}]. Use 'unsubscribe {}' to stop.", device, device),
    }
    Ok(())
}

async fn cmd_subscribe_events(shell: &mut Shell, args: &[String]) -> Result<()> {
    if args.is_empty() {
        println!("usage: subscribe-events <device> [endpoint]");
        return Ok(());
    }
    let device = args[0].clone();
    let endpoint: Option<u16> = if args.len() > 1 { Some(parse_u16(&args[1])?) } else { None };

    let node_id = shell.resolve_node_id(&device)?;
    if !shell.connections.contains_key(&node_id) {
        println!("  connecting to '{}' ...", device);
        let conn = Arc::new(shell.dm.connect(node_id).await?);
        shell.connections.insert(node_id, conn);
    }
    let conn = shell.connections.get(&node_id).unwrap().clone();

    let keep = shell.subscriptions.contains_key(&node_id);
    let res = conn.im_subscribe_request_event2(endpoint, None, None, keep).await?;

    if res.protocol_header.opcode != matc::messages::ProtocolMessageHeader::INTERACTION_OPCODE_REPORT_DATA {
        println!("unexpected subscribe response opcode 0x{:x}", res.protocol_header.opcode);
        return Ok(());
    }

    let priming = decode_event_reports(&res.tlv);
    if priming.is_empty() {
        println!("[{}] event subscription active (no priming events)", device);
    } else {
        for (ep, cl, ev, num, val) in &priming {
            let json = matc::clusters::codec::decode_event_json(*cl, *ev, val);
            println!("[{}] ep{} EVENT {} #{} = {} (current)", device, ep, event_label(*cl, *ev), num, json);
        }
    }

    conn.im_status_response(res.protocol_header.exchange_id, 1 | 2, res.message_header.message_counter).await?;

    if let std::collections::hash_map::Entry::Vacant(e) = shell.subscriptions.entry(node_id) {
        let entries: Arc<Mutex<Vec<SubscriptionEntry>>> = Arc::new(Mutex::new(Vec::new()));
        let handle = spawn_listener(conn, device.clone(), entries.clone());
        e.insert(DeviceSubscriptions { entries, handle, wildcard: None, wildcard_events: vec![endpoint] });
    } else {
        shell.subscriptions.get_mut(&node_id).unwrap().wildcard_events.push(endpoint);
    }

    match endpoint {
        Some(ep) => println!("Subscribed (events ep{}): [{}]. Use 'unsubscribe {}' to stop.", ep, device, device),
        None     => println!("Subscribed (events all): [{}]. Use 'unsubscribe {}' to stop.", device, device),
    }
    Ok(())
}

async fn cmd_unsubscribe(shell: &mut Shell, args: &[String]) -> Result<()> {
    if args.is_empty() {
        println!("usage: unsubscribe <device>");
        return Ok(());
    }
    let node_id = shell.resolve_node_id(&args[0])?;
    if let Some(ds) = shell.subscriptions.remove(&node_id) {
        ds.handle.abort();
        // Tell the device to cancel all subscriptions on this session.
        if let Some(conn) = shell.connections.get(&node_id) {
            let _ = conn.im_unsubscribe_all().await;
        }
        println!("All subscriptions cancelled for node {}.", node_id);
    } else {
        println!("No active subscriptions for node {}.", node_id);
    }
    Ok(())
}

fn cmd_subscriptions(shell: &Shell) -> Result<()> {
    if shell.subscriptions.is_empty() {
        println!("No active subscriptions.");
        return Ok(());
    }
    for (node_id, ds) in &shell.subscriptions {
        let name = shell.dm.get_device(*node_id)
            .ok().flatten()
            .map(|d| d.name)
            .unwrap_or_else(|| node_id.to_string());
        let entries = ds.entries.lock().unwrap();
        for e in entries.iter() {
            println!("  {} (node {}) ep{} {}", name, node_id, e.endpoint, e.label);
        }
        match ds.wildcard {
            Some(Some(ep)) => println!("  {} (node {}) ep{} <all attributes>", name, node_id, ep),
            Some(None)     => println!("  {} (node {}) ep* <all attributes>", name, node_id),
            None           => {}
        }
        for ep_filter in &ds.wildcard_events {
            match ep_filter {
                Some(ep) => println!("  {} (node {}) ep{} <all events>", name, node_id, ep),
                None     => println!("  {} (node {}) ep* <all events>", name, node_id),
            }
        }
    }
    Ok(())
}

fn cmd_rename(shell: &Shell, args: &[String]) -> Result<()> {
    if args.len() < 2 { println!("usage: rename <device> <new_name>"); return Ok(()); }
    let node_id = shell.resolve_node_id(&args[0])?;
    shell.dm.rename_device(node_id, &args[1])?;
    println!("Renamed node {} → '{}'.", node_id, args[1]);
    Ok(())
}

fn cmd_remove(shell: &mut Shell, args: &[String]) -> Result<()> {
    if args.is_empty() { println!("usage: remove <device>"); return Ok(()); }
    let node_id = shell.resolve_node_id(&args[0])?;
    if let Some(ds) = shell.subscriptions.remove(&node_id) {
        ds.handle.abort();
    }
    shell.connections.remove(&node_id);
    shell.dm.remove_device(node_id)?;
    println!("Removed node {}.", node_id);
    Ok(())
}

// ── Dispatch ──────────────────────────────────────────────────────────────────

async fn dispatch(shell: &mut Shell, tokens: &[String]) -> Result<bool> {
    if tokens.is_empty() {
        return Ok(true);
    }
    let cmd = tokens[0].as_str();
    let args = &tokens[1..];

    match cmd {
        "help" | "?" => print_help(),
        "quit" | "exit" | "q" => return Ok(false),

        "init" => cmd_init(args, shell.dm.base_path()).await?,

        "commission" => cmd_commission(shell, args).await?,
        "commission-discover" => cmd_commission_discover(shell, args).await?,
        "commission-ble-wifi" => cmd_commission_ble_wifi(shell, args).await?,
        "commission-ble-thread" => cmd_commission_ble_thread(shell, args).await?,
        "discover" => cmd_discover(args).await?,

        "list" | "ls" => cmd_list(shell)?,
        "status" => cmd_status(shell)?,
        "rename" => cmd_rename(shell, args)?,
        "remove" | "rm" => cmd_remove(shell, args)?,

        "connect" => cmd_connect(shell, args).await?,
        "connect-all" => cmd_connect_all(shell).await?,
        "disconnect" => cmd_disconnect(shell, args)?,

        "on" => cmd_on(shell, args).await?,
        "off" => cmd_off(shell, args).await?,
        "toggle" => cmd_toggle(shell, args).await?,
        "level" => cmd_level(shell, args).await?,
        "hue" => cmd_hue(shell, args).await?,

        "read" => cmd_read(shell, args).await?,
        "read-all" => cmd_read_all(shell, args).await?,
        "clusters" => cmd_clusters(shell, args).await?,
        "parts" => cmd_parts(shell, args).await?,

        "invoke" => cmd_invoke(shell, args).await?,

        "subscribe" => cmd_subscribe(shell, args).await?,
        "subscribe-onoff" => cmd_subscribe_onoff(shell, args).await?,
        "subscribe-all" => cmd_subscribe_all(shell, args).await?,
        "subscribe-events" => cmd_subscribe_events(shell, args).await?,
        "unsubscribe" => cmd_unsubscribe(shell, args).await?,
        "subscriptions" => cmd_subscriptions(shell)?,

        other => {
            println!("Unknown command: '{}'. Type 'help' for a list of commands.", other);
        }
    }
    Ok(true)
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = parse_args();

    env_logger::Builder::new()
        .parse_default_env()
        .target(env_logger::Target::Stderr)
        .filter_level(if args.verbose {
            log::LevelFilter::Trace
        } else {
            log::LevelFilter::Error
        })
        .format_timestamp(Some(env_logger::TimestampPrecision::Millis))
        .init();

    let data_dir = args.data_dir.clone();

    // Handle "init" as a special bootstrapping command before DeviceManager exists
    if let Some(ref run_once) = args.run_once {
        let tokens = tokenize(run_once);
        if tokens.first().map(|s| s.as_str()) == Some("init") {
            cmd_init(&tokens[1..], &data_dir).await?;
            return Ok(());
        }
    }

    // Load DeviceManager
    let dm = DeviceManager::load(&data_dir).await.map_err(|e| {
        anyhow::anyhow!(
            "Failed to load device manager from '{}': {}\n\
             Run 'cargo run --example shell -- --data-dir {} init' first.",
            data_dir, e, data_dir
        )
    })?;

    let mut shell = Shell::new(dm);

    // Non-interactive: run one command and exit
    if let Some(run_once) = args.run_once {
        let tokens = tokenize(&run_once);
        if let Err(e) = dispatch(&mut shell, &tokens).await {
            eprintln!("Error: {:#}", e);
            std::process::exit(1);
        }
        return Ok(());
    }

    // Interactive REPL
    println!("Matter shell — type 'help' for available commands.");
    println!("Data dir: {}", data_dir);

    let device_names: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec![]));
    let helper = ShellHelper {
        hinter: HistoryHinter::new(),
        device_names: device_names.clone(),
    };
    let mut rl: Editor<ShellHelper, DefaultHistory> =
        Editor::new().expect("failed to create line editor");
    rl.set_helper(Some(helper));

    let history_path = format!("{}/.history", data_dir);
    let _ = rl.load_history(&history_path); // ignore if missing on first run

    loop {
        // Refresh device names for completion before each prompt.
        if let Ok(devices) = shell.dm.list_devices() {
            *device_names.lock().unwrap() =
                devices.iter().map(|d| d.name.clone()).collect();
        }

        let prompt = {
            let devices = shell.dm.list_devices().unwrap_or_default();
            let connected = devices
                .iter()
                .filter(|d| shell.connections.contains_key(&d.node_id))
                .count();
            format!("matc [{}/{}]> ", connected, devices.len())
        };

        // readline is blocking; block_in_place yields the tokio thread
        // without spawning a background task, so Editor stays on the stack.
        let readline = tokio::task::block_in_place(|| rl.readline(&prompt));

        let line = match readline {
            Ok(l) => l,
            Err(ReadlineError::Interrupted) => {
                // Ctrl+C — cancel current input, stay in the loop
                println!("(type 'quit' or Ctrl+D to exit)");
                continue;
            }
            Err(ReadlineError::Eof) => break, // Ctrl+D
            Err(e) => {
                eprintln!("readline error: {}", e);
                break;
            }
        };

        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        rl.add_history_entry(trimmed).ok();

        let tokens = tokenize(trimmed);
        match dispatch(&mut shell, &tokens).await {
            Ok(true) => {}
            Ok(false) => break,
            Err(e) => eprintln!("Error: {:#}", e),
        }
    }

    let _ = rl.save_history(&history_path);
    println!("Goodbye.");
    Ok(())
}
