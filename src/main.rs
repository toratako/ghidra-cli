mod app;
mod cli;
mod config;
mod error;
mod filter;
mod format;
mod ghidra;
mod ipc;
mod query;

use app::{handle_bridge_command, run_command, run_setup};
use clap::Parser;
use cli::{Cli, Commands};
use std::path::PathBuf;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;

fn main() {
    let cli = Cli::parse();

    apply_global_env_overrides(&cli);

    // --- Logging setup ---
    // File layer: always writes at debug level
    let log_dir = dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("ghidra-cli");
    let _ = std::fs::create_dir_all(&log_dir);
    let file_appender = tracing_appender::rolling::daily(&log_dir, "ghidra-cli.log");
    let file_layer = tracing_subscriber::fmt::layer()
        .with_writer(file_appender)
        .with_ansi(false)
        .with_filter(tracing_subscriber::EnvFilter::new("debug"));

    // Stdout layer: only if -v/-vv/-vvv is specified
    let stdout_layer = match cli.verbose {
        1 => Some("warn"),
        2 => Some("info"),
        3.. => Some("debug"),
        _ => None,
    }
    .map(|level| {
        tracing_subscriber::fmt::layer()
            .with_writer(std::io::stderr)
            .with_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level)),
            )
    });

    tracing_subscriber::registry()
        .with(file_layer)
        .with(stdout_layer)
        .init();

    // Captured before `cli` is moved into whichever arm handles it below;
    // needed after the match to decide how verbosely to print error detail.
    let verbose = cli.verbose;
    let json_requested = cli.json;

    let result = match &cli.command {
        Commands::Setup(_) => {
            // Setup needs async for downloading
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(run_setup(cli))
        }
        Commands::Start { .. }
        | Commands::Stop { .. }
        | Commands::Restart { .. }
        | Commands::Status { .. }
        | Commands::Ping { .. }
        | Commands::Jobs { .. }
        | Commands::Cancel { .. } => handle_bridge_command(cli),
        _ => run_command(cli),
    };

    if let Err(e) = result {
        // A client-side read timeout means the CLI gave up waiting, not that
        // the job actually failed -- it may still be running server-side and
        // complete normally after this process exits (see `ghidra jobs`).
        // Give it a distinguishable prefix and exit code (EX_TEMPFAIL, 75,
        // from sysexits.h: "temporary failure; user is invited to retry") so
        // a wrapper script can tell "poll `ghidra jobs` and keep going" apart
        // from a genuine failure without string-matching stderr.
        if let Some(timeout) = e.downcast_ref::<ipc::protocol::BridgeTimeoutError>() {
            eprintln!("Timeout: {}", timeout);
            std::process::exit(75);
        }
        eprintln!("Error: {}", e);
        // Bridge errors that carry structured detail (e.g. the containing
        // function's name/entry/size on "function already exists", or the
        // conflicting data unit's type/range on a `type apply` conflict) print
        // it as JSON so callers can act on it without a follow-up round trip.
        // Gated to -vv+/--json to keep the common-case error terse.
        if let Some(bce) = e.downcast_ref::<ipc::protocol::BridgeCommandError>() {
            if verbose >= 2 || json_requested {
                if let Ok(pretty) = serde_json::to_string_pretty(&bce.detail) {
                    eprintln!("Detail: {}", pretty);
                }
            }
        }
        std::process::exit(1);
    }
}

/// Fold global CLI flags that must reach code which independently reloads
/// `Config` (e.g. the bridge launcher in `bridge.rs`) into process env vars.
///
/// Only flags that cross such a boundary belong here. `--projects-dir`, by
/// contrast, is applied in-process via `app::project::load_config` and deliberately does
/// not go through the environment.
fn apply_global_env_overrides(cli: &Cli) {
    // `--java-home` is read by `Config::get_java_home`, which the bridge launcher
    // calls after reloading config from disk — so the flag must propagate via env.
    if let Some(jh) = &cli.java_home {
        std::env::set_var("GHIDRA_CLI_JAVA_HOME", jh);
    }
}
