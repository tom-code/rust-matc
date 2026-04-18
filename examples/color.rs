//! Color Control CLI for Matter Devices
//!
//! This example provides a command-line interface for controlling color-capable
//! Matter devices (e.g., smart LED bulbs) using the Color Control cluster.
//!
//! # Usage
//!
//! ```bash
//! # Move to a specific hue
//! cargo run --example color -- --device-address 192.168.1.100:5540 move-to-hue 120 shortest 10
//!
//! # Set color temperature
//! cargo run --example color -- --device-address 192.168.1.100:5540 move-to-color-temperature 250 10
//! ```

use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use matc::clusters::codec::color_control as cc;
use matc::{certmanager, clusters, controller, transport};

const DEFAULT_LOCAL_ADDRESS: &str = "0.0.0.0:5555";
const DEFAULT_CERT_PATH: &str = "./pem";

// Matter Color Control cluster optional fields (usually 0 per spec)
const DEFAULT_OPTIONS_MASK: u8 = 0;
const DEFAULT_OPTIONS_OVERRIDE: u8 = 0;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum DirectionArg {
    Shortest,
    Longest,
    Up,
    Down,
}

impl From<DirectionArg> for clusters::codec::color_control::Direction {
    fn from(arg: DirectionArg) -> Self {
        match arg {
            DirectionArg::Shortest => Self::Shortest,
            DirectionArg::Longest => Self::Longest,
            DirectionArg::Up => Self::Up,
            DirectionArg::Down => Self::Down,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum MoveModeArg {
    Stop,
    Up,
    Down,
}

impl From<MoveModeArg> for clusters::codec::color_control::MoveMode {
    fn from(arg: MoveModeArg) -> Self {
        match arg {
            MoveModeArg::Stop => Self::Stop,
            MoveModeArg::Up => Self::Up,
            MoveModeArg::Down => Self::Down,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum StepModeArg {
    Up,
    Down,
}

impl From<StepModeArg> for clusters::codec::color_control::StepMode {
    fn from(arg: StepModeArg) -> Self {
        match arg {
            StepModeArg::Up => Self::Up,
            StepModeArg::Down => Self::Down,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ColorLoopActionArg {
    Deactivate,
    ActivateFromColorLoopStartEnhancedHue,
    ActivateFromEnhancedCurrentHue,
}

impl From<ColorLoopActionArg> for clusters::codec::color_control::ColorLoopAction {
    fn from(arg: ColorLoopActionArg) -> Self {
        match arg {
            ColorLoopActionArg::Deactivate => Self::Deactivate,
            ColorLoopActionArg::ActivateFromColorLoopStartEnhancedHue => Self::Activatefromcolorloopstartenhancedhue,
            ColorLoopActionArg::ActivateFromEnhancedCurrentHue => Self::Activatefromenhancedcurrenthue,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ColorLoopDirectionArg {
    Decrement,
    Increment,
}

impl From<ColorLoopDirectionArg> for clusters::codec::color_control::ColorLoopDirection {
    fn from(arg: ColorLoopDirectionArg) -> Self {
        match arg {
            ColorLoopDirectionArg::Decrement => Self::Decrement,
            ColorLoopDirectionArg::Increment => Self::Increment,
        }
    }
}

#[derive(Parser, Debug)]
#[command(about = "Control Matter color-capable devices")]
struct Cli {
    /// Enable verbose logging
    #[clap(long, default_value_t = false)]
    verbose: bool,

    /// Path to certificate directory
    #[clap(long, default_value_t = DEFAULT_CERT_PATH.to_string())]
    cert_path: String,

    /// Local UDP address to bind to
    #[clap(long, default_value_t = DEFAULT_LOCAL_ADDRESS.to_string())]
    local_address: String,

    /// Device address (IP:PORT) - required
    #[clap(long)]
    device_address: String,

    /// Controller ID (fabric identifier)
    #[clap(long, default_value_t = 100)]
    controller_id: u64,

    /// Device node ID
    #[clap(long, default_value_t = 300)]
    device_id: u64,

    /// Endpoint ID for the color control cluster
    #[clap(long, default_value_t = 1)]
    endpoint: u16,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    MoveToHue {
        hue: u8,
        direction: DirectionArg,
        transition_time: u16,
    },
    MoveHue {
        move_mode: MoveModeArg,
        rate: u8,
    },
    StepHue {
        step_mode: StepModeArg,
        step_size: u8,
        transition_time: u8,
    },
    MoveToSaturation {
        saturation: u8,
        transition_time: u16,
    },
    MoveSaturation {
        move_mode: MoveModeArg,
        rate: u8,
    },
    StepSaturation {
        step_mode: StepModeArg,
        step_size: u8,
        transition_time: u8,
    },
    MoveToHueAndSaturation {
        hue: u8,
        saturation: u8,
        transition_time: u16,
    },
    MoveToColor {
        color_x: u16,
        color_y: u16,
        transition_time: u16,
    },
    MoveColor {
        rate_x: i16,
        rate_y: i16,
    },
    StepColor {
        step_x: i16,
        step_y: i16,
        transition_time: u16,
    },
    MoveToColorTemperature {
        color_temperature_mireds: u16,
        transition_time: u16,
    },
    EnhancedMoveToHue {
        enhanced_hue: u16,
        direction: DirectionArg,
        transition_time: u16,
    },
    EnhancedMoveHue {
        move_mode: MoveModeArg,
        rate: u16,
    },
    EnhancedStepHue {
        step_mode: StepModeArg,
        step_size: u16,
        transition_time: u16,
    },
    EnhancedMoveToHueAndSaturation {
        enhanced_hue: u16,
        saturation: u8,
        transition_time: u16,
    },
    ColorLoopSet {
        update_flags: u8,
        action: ColorLoopActionArg,
        direction: ColorLoopDirectionArg,
        time: u16,
        start_hue: u16,
    },
    StopMoveStep,
    MoveColorTemperature {
        move_mode: MoveModeArg,
        rate: u16,
        color_temperature_minimum_mireds: u16,
        color_temperature_maximum_mireds: u16,
    },
    StepColorTemperature {
        step_mode: StepModeArg,
        step_size: u16,
        transition_time: u16,
        color_temperature_minimum_mireds: u16,
        color_temperature_maximum_mireds: u16,
    },
}


/// Creates an authenticated CASE session to a Matter device
async fn create_connection(
    local_address: &str,
    device_address: &str,
    device_id: u64,
    controller_id: u64,
    cert_path: &str,
) -> Result<controller::Connection> {
    let cm: Arc<dyn certmanager::CertManager> =
        certmanager::FileCertManager::load(cert_path)
            .with_context(|| format!("Failed to load certificates from {}", cert_path))?;

    let transport = transport::Transport::new(local_address)
        .await
        .with_context(|| format!("Failed to create transport on {}", local_address))?;

    let controller = controller::Controller::new(&cm, &transport, cm.get_fabric_id())
        .context("Failed to create controller")?;

    let connection = transport.create_connection(device_address).await;

    controller
        .auth_sigma(&connection, device_id, controller_id)
        .await
        .with_context(|| {
            format!(
                "Failed to authenticate with device {} (node_id: {})",
                device_address, device_id
            )
        })
}



/// Executes a color control command via the generated typed facade.
async fn execute_color_command(
    connection: &controller::Connection,
    endpoint: u16,
    command: Commands,
) -> Result<()> {
    let mask = DEFAULT_OPTIONS_MASK;
    let over = DEFAULT_OPTIONS_OVERRIDE;
    let ep = endpoint;

    match command {
        Commands::MoveToHue { hue, direction, transition_time } =>
            cc::move_to_hue(connection, ep, hue, direction.into(), transition_time, mask, over).await,
        Commands::MoveHue { move_mode, rate } =>
            cc::move_hue(connection, ep, move_mode.into(), rate, mask, over).await,
        Commands::StepHue { step_mode, step_size, transition_time } =>
            cc::step_hue(connection, ep, step_mode.into(), step_size, transition_time, mask, over).await,
        Commands::MoveToSaturation { saturation, transition_time } =>
            cc::move_to_saturation(connection, ep, saturation, transition_time, mask, over).await,
        Commands::MoveSaturation { move_mode, rate } =>
            cc::move_saturation(connection, ep, move_mode.into(), rate, mask, over).await,
        Commands::StepSaturation { step_mode, step_size, transition_time } =>
            cc::step_saturation(connection, ep, step_mode.into(), step_size, transition_time, mask, over).await,
        Commands::MoveToHueAndSaturation { hue, saturation, transition_time } =>
            cc::move_to_hue_and_saturation(connection, ep, hue, saturation, transition_time, mask, over).await,
        Commands::MoveToColor { color_x, color_y, transition_time } =>
            cc::move_to_color(connection, ep, color_x, color_y, transition_time, mask, over).await,
        Commands::MoveColor { rate_x, rate_y } =>
            cc::move_color(connection, ep, rate_x, rate_y, mask, over).await,
        Commands::StepColor { step_x, step_y, transition_time } =>
            cc::step_color(connection, ep, step_x, step_y, transition_time, mask, over).await,
        Commands::MoveToColorTemperature { color_temperature_mireds, transition_time } =>
            cc::move_to_color_temperature(connection, ep, color_temperature_mireds, transition_time, mask, over).await,
        Commands::EnhancedMoveToHue { enhanced_hue, direction, transition_time } =>
            cc::enhanced_move_to_hue(connection, ep, enhanced_hue, direction.into(), transition_time, mask, over).await,
        Commands::EnhancedMoveHue { move_mode, rate } =>
            cc::enhanced_move_hue(connection, ep, move_mode.into(), rate, mask, over).await,
        Commands::EnhancedStepHue { step_mode, step_size, transition_time } =>
            cc::enhanced_step_hue(connection, ep, step_mode.into(), step_size, transition_time, mask, over).await,
        Commands::EnhancedMoveToHueAndSaturation { enhanced_hue, saturation, transition_time } =>
            cc::enhanced_move_to_hue_and_saturation(connection, ep, enhanced_hue, saturation, transition_time, mask, over).await,
        Commands::ColorLoopSet { update_flags, action, direction, time, start_hue } =>
            cc::color_loop_set(connection, ep, update_flags, action.into(), direction.into(), time, start_hue, mask, over).await,
        Commands::StopMoveStep =>
            cc::stop_move_step(connection, ep, mask, over).await,
        Commands::MoveColorTemperature { move_mode, rate, color_temperature_minimum_mireds, color_temperature_maximum_mireds } =>
            cc::move_color_temperature(connection, ep, move_mode.into(), rate, color_temperature_minimum_mireds, color_temperature_maximum_mireds, mask, over).await,
        Commands::StepColorTemperature { step_mode, step_size, transition_time, color_temperature_minimum_mireds, color_temperature_maximum_mireds } =>
            cc::step_color_temperature(connection, ep, step_mode.into(), step_size, transition_time, color_temperature_minimum_mireds, color_temperature_maximum_mireds, mask, over).await,
    }
    .context("Failed to invoke color control command")?;

    println!("Command successful.");
    Ok(())
}

/// Configures logging based on verbosity level
fn setup_logging(verbose: bool) {
    let log_level = if verbose {
        log::LevelFilter::Trace
    } else {
        log::LevelFilter::Error
    };

    env_logger::Builder::new()
        .parse_default_env()
        .target(env_logger::Target::Stdout)
        .filter_level(log_level)
        .format_line_number(true)
        .format_file(true)
        .format_timestamp(Some(env_logger::TimestampPrecision::Millis))
        .init();
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    setup_logging(cli.verbose);

    // Create authenticated connection to device
    let connection = create_connection(
        &cli.local_address,
        &cli.device_address,
        cli.device_id,
        cli.controller_id,
        &cli.cert_path,
    )
    .await?;

    // Execute the color control command
    execute_color_command(&connection, cli.endpoint, cli.command).await?;

    Ok(())
}
