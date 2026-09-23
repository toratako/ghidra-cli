mod address;
mod app;
mod cli;
mod config;
mod error;
mod filter;
mod format;
mod ghidra;
mod ipc;
mod query;
mod terminal;

use app::{handle_management_command, run_command};
use clap::Parser;
use cli::{Cli, Commands};
use serde_json::Value;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;

fn main() {
    let cli = parse_cli();

    apply_global_env_overrides(&cli);

    // --- Logging setup ---
    // File layer: always writes at debug level
    let log_dir = dirs::data_local_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("ghidra-cli");
    let file_layer = tracing_appender::rolling::RollingFileAppender::builder()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix("ghidra-cli.log")
        .build(&log_dir)
        .map_err(|error| {
            if cli.verbose > 0 && !cli.quiet {
                eprintln!("File logging unavailable: {error}");
            }
        })
        .ok()
        .map(|file_appender| {
            tracing_subscriber::fmt::layer()
                .with_writer(file_appender)
                .with_ansi(false)
                .with_filter(tracing_subscriber::EnvFilter::new("debug"))
        });

    // Console diagnostics are opt-in and always go to stderr.
    let stderr_layer = match cli.verbose {
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
        .with(stderr_layer)
        .init();

    // Captured before `cli` is moved into whichever arm handles it below;
    // needed after the match to decide how verbosely to print error detail.
    let verbose = cli.verbose;
    let output = app::Output::new(&cli);

    let result = match &cli.command {
        Commands::Bridge(_) | Commands::Job(_) => handle_management_command(cli),
        _ => run_command(cli),
    };

    if let Err(e) = result {
        let (code, diagnostic) = format_error(&e, output, verbose);
        use std::io::Write;
        let _ = writeln!(std::io::stderr().lock(), "{diagnostic}");
        std::process::exit(code);
    }
}

fn parse_cli() -> Cli {
    let args: Vec<_> = std::env::args_os().collect();
    match Cli::try_parse_from(&args) {
        Ok(cli) => cli,
        Err(error) => {
            if !error.use_stderr() {
                error.exit(); // Help and version retain clap's successful text output.
            }
            // A failed parse has no Cli. Recover only presentation options, stopping
            // at `--` so script arguments and operands never select our output mode.
            use std::io::{IsTerminal, Write};
            let mut output =
                app::Output::diagnostic(!std::io::stdout().is_terminal(), false, false);
            let mut format = None;
            let mut args = args.iter().skip(1).take_while(|arg| *arg != "--");
            while let Some(arg) = args.next() {
                if arg == "--json" {
                    output.json = true;
                } else if arg == "--pretty" {
                    output.json = true;
                    output.pretty = true;
                } else if arg == "--format" {
                    format = args
                        .next()
                        .and_then(|arg| arg.to_str())
                        .and_then(|f| f.parse::<format::OutputFormat>().ok());
                } else if let Some(value) =
                    arg.to_str().and_then(|arg| arg.strip_prefix("--format="))
                {
                    format = value.parse::<format::OutputFormat>().ok();
                }
            }
            if let Some(format) = format {
                output.json = matches!(
                    format,
                    format::OutputFormat::Json
                        | format::OutputFormat::JsonCompact
                        | format::OutputFormat::JsonStream
                );
                output.pretty = matches!(format, format::OutputFormat::Json);
            }
            if output.json {
                let value = serde_json::json!({"status": "error", "message": error.to_string(), "exit_code": error.exit_code()});
                let _ = writeln!(
                    std::io::stderr().lock(),
                    "{}",
                    output
                        .json_string(&value)
                        .expect("parser error is serializable")
                );
                std::process::exit(error.exit_code());
            }
            error.exit();
        }
    }
}

fn format_error(error: &anyhow::Error, output: app::Output, verbose: u8) -> (i32, String) {
    // A timeout may leave a job running; preserve EX_TEMPFAIL so callers can poll jobs.
    let timeout = error
        .downcast_ref::<ipc::protocol::BridgeTimeoutError>()
        .is_some();
    let detail = error::diagnostic_detail(error);
    let pending = detail["result_state"] == "pending";
    let code = if timeout || pending { 75 } else { 1 };
    let detail = detail.as_object().filter(|map| !map.is_empty());
    let message = if error
        .downcast_ref::<ipc::protocol::BridgeCommandError>()
        .is_some()
    {
        error.to_string()
    } else {
        format!("{error:#}")
    };
    if output.json {
        let mut value = serde_json::json!({
            "status": if timeout { "timeout" } else if pending { "pending" } else { "error" },
            "message": message,
            "exit_code": code,
        });
        if let Some(detail) = detail {
            value["detail"] = serde_json::Value::Object(detail.clone());
        }
        (
            code,
            output
                .json_string(&value)
                .expect("error JSON is serializable"),
        )
    } else {
        let prefix = if timeout { "Timeout" } else { "Error" };
        let mut text = format!("{prefix}: {message}");
        if let Some(detail) = detail {
            if detail.get("rolled_back").and_then(Value::as_bool) == Some(true) {
                text.push_str("\nChanges from this command were rolled back.");
            } else if detail.get("partial_changes_saved").and_then(Value::as_bool) == Some(true) {
                text.push_str("\nPartial changes were saved; inspect the program before retrying.");
            }
        }
        if verbose >= 2 {
            if let Some(detail) = detail {
                text.push_str(&format!(
                    "\nDetail: {}",
                    serde_json::Value::Object(detail.clone())
                ));
            }
        }
        (code, text)
    }
}

/// Fold global CLI flags that must reach code which independently reloads
/// `Config` (e.g. the bridge launcher in `ghidra/bridge/startup.rs`) into process env vars.
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    #[test]
    fn structured_errors_preserve_detail_and_timeout_exit_code() {
        for pretty in [false, true] {
            let output = app::Output::diagnostic(true, pretty, false);
            let error = anyhow::Error::new(ipc::protocol::BridgeCommandError {
                message: "function already exists".to_string(),
                detail: json!({"entry": "00401000", "name": "main"}),
            });
            let (code, text) = format_error(&error, output, 0);
            let value: Value = serde_json::from_str(&text).unwrap();
            assert_eq!(code, 1);
            assert_eq!(value["detail"]["entry"], "00401000");
            let timeout = anyhow::Error::new(ipc::protocol::BridgeTimeoutError {
                command: "analysis_run".to_string(),
                timeout_secs: 30,
            });
            let (code, text) = format_error(&timeout, output, 0);
            let value: Value = serde_json::from_str(&text).unwrap();
            assert_eq!(code, 75);
            assert_eq!(value["exit_code"], 75);
            assert_eq!(value["status"], "timeout");
        }
    }

    #[test]
    fn explicit_text_format_keeps_human_errors() {
        let cli = Cli::try_parse_from([
            "ghidra-cli",
            "--json",
            "function",
            "list",
            "--format",
            "table",
        ])
        .unwrap();
        let output = app::Output::new(&cli);
        let (_, text) = format_error(&anyhow::anyhow!("failed operation"), output, 0);
        assert_eq!(text, "Error: failed operation");
    }

    #[test]
    fn human_errors_explain_edit_outcomes_without_verbose_details() {
        let output = app::Output::diagnostic(false, false, false);
        for (detail, expected) in [
            (
                json!({"rolled_back": true}),
                "Changes from this command were rolled back.",
            ),
            (
                json!({"partial_changes_saved": true}),
                "Partial changes were saved; inspect the program before retrying.",
            ),
        ] {
            let error = anyhow::Error::new(ipc::protocol::BridgeCommandError {
                message: "edit failed".into(),
                detail: detail.clone(),
            });
            let (code, text) = format_error(&error, output, 0);
            assert_eq!(code, 1);
            assert_eq!(text, format!("Error: edit failed\n{expected}"));
            let (_, json_text) =
                format_error(&error, app::Output::diagnostic(true, false, false), 0);
            let value: Value = serde_json::from_str(&json_text).unwrap();
            assert_eq!(value["detail"], detail);
            assert_eq!(value["message"], "edit failed");
        }
    }
}
