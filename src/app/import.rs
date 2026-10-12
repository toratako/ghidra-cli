//! Import workflow: loader validation, durable import, and analysis sequencing.

mod options;
mod progress;

use options::build_oneshot_import_options;
pub(super) use options::validate_options;
use progress::ImportProgress;

use super::project::project_has_program_data;
use crate::cli::{Cli, ImportArgs};
use crate::ghidra::bridge::{self, BridgeStartMode};
use crate::ghidra::installation::Installation;
use crate::ipc::client::ProgramSelection;
use serde_json::json;
use std::path::{Path, PathBuf};

pub(super) fn run_import(
    cli: &Cli,
    args: &ImportArgs,
    project_path: &Path,
    installation: &Installation,
    selection: &ProgramSelection,
) -> anyhow::Result<serde_json::Value> {
    let mut progress = ImportProgress::new(args.no_analyze);
    run_import_steps(
        cli,
        args,
        project_path,
        installation,
        &mut progress,
        selection,
    )
    .map_err(|error| progress.failure(error, project_path))
}

fn run_import_steps(
    cli: &Cli,
    args: &ImportArgs,
    project_path: &Path,
    installation: &Installation,
    progress: &mut ImportProgress,
    selection: &ProgramSelection,
) -> anyhow::Result<serde_json::Value> {
    let output = crate::app::Output::new(cli);
    let binary_path = PathBuf::from(&args.binary);
    anyhow::ensure!(binary_path.is_file(), "Binary not found: {}", args.binary);
    // The importer derives the default saved name from this path. Resolve the
    // CLI's CWD without replacing a symlink's input name with its target name.
    let binary_path = std::path::absolute(binary_path)?;
    let binary_path = dunce::simplified(&binary_path).to_path_buf();
    let (options, explicit_loader) = build_oneshot_import_options(args)?;
    let running = bridge::is_bridge_running(project_path);
    let one_shot =
        explicit_loader || (running.is_none() && !project_has_program_data(project_path));
    let (client, name) = if one_shot {
        if running.is_some() {
            progress.stage = "bridge.stop";
            bridge::stop_bridge(project_path)?;
        }
        output.progress("Importing and saving program...");
        progress.stage = "import.headless";
        progress.imported = "unknown";
        progress.analysis = if args.no_analyze {
            "skipped"
        } else {
            "unknown"
        };
        let receipt: bridge::OneShotImportReceipt =
            bridge::import_oneshot(project_path, &binary_path, installation, &options)?;
        let name = receipt.program.clone();
        progress.receipt = Some(serde_json::to_value(receipt)?);
        progress.imported = "saved";
        progress.analysis = if args.no_analyze {
            "skipped"
        } else {
            "completed"
        };
        progress.program = Some(name.clone());
        progress.stage = "bridge.start";
        output.progress("Import saved. Starting Ghidra bridge...");
        let port = bridge::ensure_bridge_running(
            project_path,
            installation,
            BridgeStartMode::Process {
                program_name: name.clone(),
            },
        )?;
        (
            super::connect_program_bridge(port)?.with_selection(selection.clone()),
            name,
        )
    } else {
        progress.stage = "bridge.start";
        let client = if let Some(port) = running {
            super::connect_program_bridge(port)?
        } else {
            super::connect_program_bridge(bridge::ensure_bridge_running(
                project_path,
                installation,
                BridgeStartMode::Project,
            )?)?
        }
        .with_selection(selection.clone());
        progress.stage = "import.load";
        progress.imported = "unknown";
        let result =
            client.import_binary(&binary_path.to_string_lossy(), options.program.as_deref())?;
        let name = result["program"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Import did not return its saved program name"))?
            .to_owned();
        progress.imported = "saved";
        progress.program = Some(name.clone());
        progress.receipt = Some(result);
        (client, name)
    };
    let analyze = if args.no_analyze {
        progress.stage = "program.open";
        client.open_program(&name)?;
        progress.analysis = "skipped";
        json!(null)
    } else if !one_shot {
        progress.stage = "import.analysis";
        progress.analysis = "unknown";
        let result = client.with_program(&name).analysis_run(None, None, false)?;
        progress.analysis = "completed";
        result
    } else {
        progress.stage = "program.info";
        let info = client.with_program(&name).program_info()?;
        json!({"status": "success", "program": name, "function_count": info.get("function_count"), "durable": true})
    };
    Ok(
        json!({"command": "program import", "program": name, "status": "success", "data": {"import": progress.receipt, "analyze": analyze}}),
    )
}
