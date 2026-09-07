//! Import workflow: loader validation, durable import, and analysis sequencing.

use super::project::project_has_program_data;
use crate::cli::{Cli, ImportArgs};
use crate::ghidra::bridge::{self, BridgeStartMode};
use crate::ipc::client::BridgeClient;
use serde_json::json;
use std::path::{Path, PathBuf};

pub(super) fn run_import(
    cli: &Cli,
    args: &ImportArgs,
    project_path: &Path,
    ghidra_install_dir: &Path,
) -> anyhow::Result<serde_json::Value> {
    let binary_path = PathBuf::from(&args.binary);
    if !binary_path.exists() {
        anyhow::bail!("Binary not found: {}", args.binary);
    }
    let (one_shot_options, explicit_loader_control) = build_oneshot_import_options(args)?;

    // Acquire a bridge connection, the imported program's name, and whether
    // analysis still needs to run over TCP. Existing projects import through
    // the live bridge and therefore analyze afterwards. A brand-new project
    // uses the short-lived one-shot importer, which performs durable analysis
    // before the persistent bridge starts (unless --no-analyze was requested).
    let (client, program_name, needs_tcp_analysis) = if explicit_loader_control {
        // Loader/language selection is a Ghidra headless-import concern.
        // The persistent bridge's AutoImporter path only supports best-guess
        // loading, so stop any live bridge, perform a short-lived durable
        // headless import with the requested loader options, then reopen it.
        if bridge::is_bridge_running(project_path).is_some() {
            if !cli.quiet {
                eprintln!("Stopping bridge for explicit loader import...");
            }
            bridge::stop_bridge(project_path)?;
        }
        if !cli.quiet {
            eprintln!("Importing with explicit Ghidra loader options...");
        }
        let name = bridge::import_oneshot(
            project_path,
            &binary_path,
            ghidra_install_dir,
            &one_shot_options,
        )?;
        if !cli.quiet {
            eprintln!("Starting Ghidra bridge...");
        }
        let port = bridge::ensure_bridge_running(
            project_path,
            ghidra_install_dir,
            BridgeStartMode::Process {
                program_name: name.clone(),
            },
        )?;
        let client = BridgeClient::new(port);
        client.open_program(&name)?;
        (client, name, false)
    } else if let Some(port) = bridge::is_bridge_running(project_path) {
        // is_bridge_running() already proved the bridge process is alive
        // and its socket is accepting; a busy bridge just queues this
        // request, so there is no pre-flight ping gate to fail here.
        let client = BridgeClient::new(port);
        if !cli.quiet {
            eprintln!("Importing into running bridge...");
        }
        let result = client.import_binary(&args.binary, args.program.as_deref())?;
        let name = args.program.clone().unwrap_or_else(|| {
            result
                .get("program")
                .and_then(|p| p.as_str())
                .unwrap_or("unknown")
                .to_string()
        });
        client.open_program(&name)?;
        (client, name, true)
    } else if project_has_program_data(project_path) {
        if !cli.quiet {
            eprintln!("Starting Ghidra bridge...");
        }
        let port = bridge::ensure_bridge_running(
            project_path,
            ghidra_install_dir,
            BridgeStartMode::Project,
        )?;
        let client = BridgeClient::new(port);
        let result = client.import_binary(&args.binary, args.program.as_deref())?;
        let name = args.program.clone().unwrap_or_else(|| {
            result
                .get("program")
                .and_then(|p| p.as_str())
                .unwrap_or("unknown")
                .to_string()
        });
        client.open_program(&name)?;
        (client, name, true)
    } else {
        if !cli.quiet {
            eprintln!("Initializing project (importing {})...", args.binary);
        }
        // Brand-new or stale empty project: initialize it with a clean, short-lived
        // one-shot import that durably commits the program, then start
        // the persistent bridge in Process mode against the committed
        // program.
        let name = bridge::import_oneshot(
            project_path,
            &binary_path,
            ghidra_install_dir,
            &one_shot_options,
        )?;
        if !cli.quiet {
            eprintln!("Starting Ghidra bridge...");
        }
        let port = bridge::ensure_bridge_running(
            project_path,
            ghidra_install_dir,
            BridgeStartMode::Process {
                program_name: name.clone(),
            },
        )?;
        let client = BridgeClient::new(port);
        client.open_program(&name)?;
        (client, name, false)
    };

    // Existing projects import over TCP and still need explicit analysis.
    // Fresh projects were already analyzed durably by import_oneshot(), so
    // re-running analyzeAll here would duplicate the most expensive step.
    let analyze_data = if args.no_analyze {
        if !cli.quiet {
            eprintln!("Skipping analysis (--no-analyze).");
        }
        json!(null)
    } else if needs_tcp_analysis {
        if !cli.quiet {
            eprintln!("Analyzing {}...", program_name);
        }
        let d = client.analyze()?;
        if !cli.quiet {
            eprintln!("Analysis complete!");
        }
        d
    } else {
        let info = client.program_info()?;
        json!({
            "status": "success",
            "program": program_name,
            "function_count": info.get("function_count").cloned().unwrap_or(json!(null)),
            "durable": true
        })
    };

    if !cli.quiet {
        eprintln!("Successfully imported as: {}", program_name);
    }
    Ok(json!({
        "command": "import",
        "program": program_name,
        "status": "success",
        "data": { "analyze": analyze_data }
    }))
}

fn build_oneshot_import_options(
    args: &ImportArgs,
) -> anyhow::Result<(bridge::OneShotImportOptions, bool)> {
    let binary_loader_fields = args.base_address.is_some()
        || args.block_name.is_some()
        || args.file_offset.is_some()
        || args.length.is_some();

    if binary_loader_fields
        && args
            .loader
            .as_deref()
            .is_some_and(|loader| loader != "BinaryLoader")
    {
        anyhow::bail!(
            "--base-address/--block-name/--file-offset/--length are BinaryLoader options"
        );
    }

    let loader = args
        .loader
        .clone()
        .or_else(|| binary_loader_fields.then(|| "BinaryLoader".to_string()));

    let mut loader_options: Vec<(String, String)> = Vec::new();
    if let Some(value) = &args.base_address {
        loader_options.push(("baseAddr".to_string(), value.clone()));
    }
    if let Some(value) = &args.block_name {
        loader_options.push(("blockName".to_string(), value.clone()));
    }
    if let Some(value) = &args.file_offset {
        loader_options.push(("fileOffset".to_string(), value.clone()));
    }
    if let Some(value) = &args.length {
        loader_options.push(("length".to_string(), value.clone()));
    }

    for raw in &args.loader_options {
        let (name, value) = raw.split_once('=').ok_or_else(|| {
            anyhow::anyhow!("Invalid --loader-option '{}': expected NAME=VALUE", raw)
        })?;
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            anyhow::bail!(
                "Invalid loader option name '{}': use only letters, digits, '-' or '_'",
                name
            );
        }
        if value.is_empty() {
            anyhow::bail!("Invalid --loader-option '{}': value must not be empty", raw);
        }
        loader_options.push((name.to_string(), value.to_string()));
    }

    let explicit_loader_control = loader.is_some()
        || args.language.is_some()
        || args.compiler_spec.is_some()
        || !loader_options.is_empty();

    Ok((
        bridge::OneShotImportOptions {
            analyze: !args.no_analyze,
            loader,
            language: args.language.clone(),
            compiler_spec: args.compiler_spec.clone(),
            loader_options,
        },
        explicit_loader_control,
    ))
}
