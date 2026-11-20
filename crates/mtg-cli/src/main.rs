//! Pure-Rust Linux MTProto Proxy (`mtg-proxy`) binary entrypoint.
//!
//! - Uses `tikv-jemallocator` with `percpu_arena:percpu`, fast dirty/muzzy
//!   page decay (`1s`), and background threads for minimal Linux RSS under
//!   100k+ concurrent streams.
//! - Implements all 8 CLI subcommands (`run`, `simple-run`, `generate-secret`,
//!   `access`, `doctor`, `rotate-secret`, `web-relay`, `generate-web-key`) and
//!   `-v` / `--version` with 100% drop-in parity.

mod cmd_access;
mod cmd_doctor;
mod cmd_rotate;
mod cmd_run;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use mtg_core::{Secret, SecretMode};
use tikv_jemallocator::Jemalloc;
use tracing_subscriber::EnvFilter;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

/// Tune jemalloc for ultra-low Linux RSS (`percpu_arena:percpu` = 1 arena per
/// physical CPU instead of 4×NCPUS, 1s dirty/muzzy page return to Linux kernel).
#[unsafe(export_name = "_rjem_malloc_conf")]
pub static MALLOC_CONF: &[u8] =
    b"percpu_arena:percpu,dirty_decay_ms:1000,muzzy_decay_ms:1000,background_thread:true\0";

/// Build version string reported by `-v`, `--version`, `version`, and CLI banners.
pub const VERSION: &str = env!("MTG_FULL_VERSION");

#[derive(Debug, Parser)]
#[command(
    name = "mtg-proxy",
    version = VERSION,
    about = "Ultra-high-performance Linux-native Telegram MTProto proxy (pure Rust)",
    disable_version_flag = true
)]
struct Cli {
    /// Print version.
    #[arg(short = 'v', long = "version", action = clap::ArgAction::Version)]
    version: (),

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Generate new proxy secret.
    GenerateSecret {
        /// Hostname to use for domain fronting. Required by (and only by) the ee mode.
        hostname: Option<String>,
        /// Print secret in hex encoding.
        #[arg(short = 'x', long = "hex")]
        hex: bool,
        /// Secret wire form: ee (FakeTLS), dd or plain.
        #[arg(long = "mode", default_value = "ee")]
        mode: String,
    },

    /// Check that proxy can run correctly.
    Doctor {
        /// Path to the configuration file.
        config_path: PathBuf,
        /// Skip the native network connectivity check.
        #[arg(long = "skip-native-check")]
        skip_native_check: bool,
    },

    /// Print access information.
    Access {
        /// Path to the configuration file.
        config_path: PathBuf,
        /// Public IPv4 address for proxy. By default it is resolved via remote website.
        #[arg(short = 'i', long = "ipv4")]
        ipv4: Option<std::net::IpAddr>,
        /// Public IPv6 address for proxy. By default it is resolved via remote website.
        #[arg(short = 'I', long = "ipv6")]
        ipv6: Option<std::net::IpAddr>,
        /// Port number. Default port is taken from configuration file, bind-to parameter.
        #[arg(short = 'p', long = "port")]
        port: Option<u16>,
        /// Print secret in hex encoding.
        #[arg(short = 'x', long = "hex")]
        hex: bool,
    },

    /// Run proxy.
    Run {
        /// Path to the configuration file.
        config_path: PathBuf,
        /// Verify the configuration and exit without listening.
        #[arg(long = "check")]
        check: bool,
        /// Override pinned worker thread count (defaults to available CPU cores).
        #[arg(long = "workers", default_value_t = 0)]
        workers: usize,
        /// Skip Linux io_uring capability probe at startup (recommended under strict container seccomp profiles).
        #[arg(long = "epoll")]
        epoll: bool,
    },

    /// Run proxy without config file.
    SimpleRun(cmd_run::SimpleRunArgs),

    /// Run the WEB proxy relay for the secrets in a config file.
    WebRelay {
        /// Path to the configuration file.
        config_path: PathBuf,
        /// Verify the [web] configuration and exit without listening.
        #[arg(long = "check")]
        check: bool,
    },

    /// Generate the WEB relay token signing key.
    GenerateWebKey {
        /// Where to write the 32-byte signing key.
        path: PathBuf,
    },

    /// Give a secret a new key, and keep the previous one accepted for an overlap.
    #[command(name = "rotate-secret")]
    RotateSecret(cmd_rotate::RotateArgs),

    /// Print version.
    Version,
}

pub fn init_logging(debug: bool) {
    let default_level = if debug { "debug" } else { "info" };
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level));
    let _ = tracing_subscriber::fmt()
        .json()
        .with_writer(std::io::stderr)
        .with_env_filter(filter)
        .with_current_span(false)
        .try_init();
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("cannot start async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    let res: anyhow::Result<bool> = rt.block_on(async move {
        match cli.command {
            Commands::GenerateSecret {
                hostname,
                hex,
                mode,
            } => {
                let parsed_mode: SecretMode = mode
                    .parse()
                    .map_err(|e| anyhow::anyhow!("incorrect mode: {e}"))?;
                let host = hostname.as_deref().unwrap_or("");
                let secret = Secret::generate_mode(parsed_mode, host)
                    .map_err(|e| anyhow::anyhow!("cannot generate a secret: {e}"))?;
                if hex {
                    println!("{}", secret.encode_hex());
                } else {
                    println!("{}", secret.encode_base64());
                }
                Ok(true)
            }
            Commands::Run {
                config_path,
                check,
                workers,
                epoll,
            } => {
                cmd_run::execute_run(&config_path, check, workers, epoll).await?;
                Ok(true)
            }
            Commands::SimpleRun(args) => {
                cmd_run::execute_simple_run(args).await?;
                Ok(true)
            }
            Commands::Access {
                config_path,
                ipv4,
                ipv6,
                port,
                hex,
            } => {
                cmd_access::execute_access(&config_path, ipv4, ipv6, port, hex).await?;
                Ok(true)
            }
            Commands::Doctor {
                config_path,
                skip_native_check,
            } => cmd_doctor::execute_doctor(&config_path, skip_native_check).await,
            Commands::RotateSecret(args) => {
                cmd_rotate::execute_rotate(args).await?;
                Ok(true)
            }
            Commands::GenerateWebKey { path } => {
                mtg_webrelay::generate_token_key(&path)?;
                println!("Wrote a WEB relay signing key to {}", path.display());
                Ok(true)
            }
            Commands::WebRelay { config_path, check } => {
                let conf = cmd_run::read_and_validate_config(&config_path)?;
                init_logging(conf.debug.unwrap_or(false));
                mtg_webrelay::run_web_relay(&conf, &config_path, VERSION, check).await?;
                Ok(true)
            }
            Commands::Version => {
                println!("{VERSION}");
                Ok(true)
            }
        }
    });

    match res {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
