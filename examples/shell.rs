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
    "init", "commission", "commission-discover", "discover",
    "connect", "connect-all", "disconnect",
    "on", "off", "toggle", "level", "hue",
    "read", "read-all", "clusters", "parts", "invoke",
    "rename", "remove",
];

/// Commands whose first argument is a device name/id.
const DEVICE_COMMANDS: &[&str] = &[
    "on", "off", "toggle", "level", "hue",
    "read", "read-all", "clusters", "parts", "invoke",
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

struct Shell {
    dm: DeviceManager,
    /// node_id → active CASE-authenticated connection
    connections: HashMap<u64, Connection>,
}

impl Shell {
    fn new(dm: DeviceManager) -> Self {
        Self { dm, connections: HashMap::new() }
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
        let conn = self.dm.connect(node_id).await?;
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

        match try1 {
            Ok(v) => return Ok(v),
            Err(_) => {}
        }

        self.connections.remove(&node_id);
        println!("  reconnecting to {} (node {})…", device, node_id);
        let conn = self.dm.connect(node_id).await?;
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
    let conn = shell.dm.commission(addr, pin, node_id, name).await?;
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
    let conn = shell.dm.commission_with_code(code, node_id, name).await?;
    println!("Commissioned '{}' (node {}).", name, node_id);
    shell.connections.insert(node_id, conn);
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
    let conn = shell.dm.connect(node_id).await?;
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
                shell.connections.insert(node_id, conn);
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
        let conn = shell.dm.connect(node_id).await?;
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

        "init" => cmd_init(args, &shell.dm.base_path().to_string()).await?,

        "commission" => cmd_commission(shell, args).await?,
        "commission-discover" => cmd_commission_discover(shell, args).await?,
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
