//! Import workflow: loader validation, durable import, and analysis sequencing.

use super::project::project_has_program_data;
use crate::cli::{Cli, ImportArgs};
use crate::ghidra::bridge::{self, BridgeStartMode};
use crate::ipc::client::BridgeClient;
use serde_json::json;
use std::path::{Path, PathBuf};

struct ImportProgress {
    stage: &'static str,
    imported: &'static str,
    analysis: &'static str,
    program: Option<String>,
}

pub(super) fn run_import(
    cli: &Cli,
    args: &ImportArgs,
    project_path: &Path,
    ghidra_install_dir: &Path,
) -> anyhow::Result<serde_json::Value> {
    let mut progress = ImportProgress {
        stage: "import.validate",
        imported: "not_started",
        analysis: if args.no_analyze {
            "skipped"
        } else {
            "not_started"
        },
        program: None,
    };
    run_import_steps(cli, args, project_path, ghidra_install_dir, &mut progress)
        .map_err(|error| import_failure(error, project_path, &progress))
}

fn import_failure(
    error: anyhow::Error,
    project: &Path,
    progress: &ImportProgress,
) -> anyhow::Error {
    let mut detail = crate::error::diagnostic_detail(&error);
    let fields = detail.as_object_mut().unwrap();
    fields.entry("stage").or_insert(json!(progress.stage));
    fields.insert("workflow_stage".into(), json!(progress.stage));
    fields
        .entry("import_status")
        .or_insert(json!(progress.imported));
    fields
        .entry("analysis_status")
        .or_insert(json!(progress.analysis));
    fields.insert("project".into(), json!(project));
    if let Some(program) = &progress.program {
        fields.insert("program".into(), json!(program));
    }
    let mut message = format!(
        "{} failed: {error:#}. Import: {}; analysis: {}",
        progress.stage,
        detail["import_status"].as_str().unwrap_or("unknown"),
        detail["analysis_status"].as_str().unwrap_or("unknown")
    );
    if detail["import_status"] == "saved" {
        if let Some(program) = detail["program"].as_str() {
            let command = if error
                .downcast_ref::<crate::ipc::protocol::BridgeTimeoutError>()
                .is_some()
            {
                vec![
                    "ghidra-cli".to_owned(),
                    "job".into(),
                    "list".into(),
                    "--project".into(),
                    project.to_string_lossy().into_owned(),
                ]
            } else if detail["save_failed"] == true {
                vec![
                    "ghidra-cli".into(),
                    "program".into(),
                    "save".into(),
                    "--project".into(),
                    project.to_string_lossy().into_owned(),
                    "--program".into(),
                    program.into(),
                ]
            } else {
                let mut command = vec!["ghidra-cli".to_owned()];
                if detail["analysis_status"] == "completed"
                    || detail["analysis_status"] == "skipped"
                {
                    command.extend(["bridge".into(), "start".into()]);
                } else {
                    command.push("analyze".into());
                }
                command.extend([
                    "--project".into(),
                    project.to_string_lossy().into_owned(),
                    "--program".into(),
                    program.into(),
                ]);
                command
            };
            message.push_str(&format!(
                ". Do not re-import. After resolving the cause, recovery arguments: {}",
                json!(command)
            ));
            detail["recovery"] = json!(command);
        }
    }
    error.context(crate::ipc::protocol::BridgeCommandError { message, detail })
}

fn run_import_steps(
    cli: &Cli,
    args: &ImportArgs,
    project_path: &Path,
    ghidra_install_dir: &Path,
    progress: &mut ImportProgress,
) -> anyhow::Result<serde_json::Value> {
    let output = crate::app::Output::new(cli);
    let binary_path = PathBuf::from(&args.binary);
    anyhow::ensure!(binary_path.is_file(), "Binary not found: {}", args.binary);
    let binary_path = dunce::canonicalize(binary_path)?;
    let (mut options, explicit_loader) = build_oneshot_import_options(args)?;
    options.program = args.program.clone().or_else(|| cli.program.clone());
    if let Some(name) = &options.program {
        anyhow::ensure!(
            !name.trim().is_empty() && name != "." && name != ".." && !name.contains(['/', '\\']),
            "--program must be a single non-empty file name"
        );
    }
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
        let name =
            bridge::import_oneshot(project_path, &binary_path, ghidra_install_dir, &options)?;
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
            ghidra_install_dir,
            BridgeStartMode::Process {
                program_name: name.clone(),
            },
        )?;
        (BridgeClient::new(port), name)
    } else {
        progress.stage = "bridge.start";
        let client = if let Some(port) = running {
            let client =
                super::ensure_autosave_bridge(port, project_path, ghidra_install_dir, output)?;
            if client.bridge_info()?["named_import"] == true {
                client
            } else {
                // Check the capability before importing: never replay an import
                // against a bridge that already saved under the wrong name.
                let selected = super::current_program_path(&client)?;
                bridge::stop_bridge(project_path)?;
                let mode = selected.map_or(BridgeStartMode::Project, |program_name| {
                    BridgeStartMode::Process { program_name }
                });
                let client = BridgeClient::new(bridge::ensure_bridge_running(
                    project_path,
                    ghidra_install_dir,
                    mode,
                )?);
                anyhow::ensure!(
                    client.bridge_info()?["named_import"] == true,
                    "Bridge does not support named imports; no import was sent"
                );
                client
            }
        } else {
            BridgeClient::new(bridge::ensure_bridge_running(
                project_path,
                ghidra_install_dir,
                BridgeStartMode::Project,
            )?)
        };
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
        (client, name)
    };
    progress.stage = "program.open";
    client.open_program(&name)?;
    let analyze = if args.no_analyze {
        progress.analysis = "skipped";
        json!(null)
    } else if !one_shot {
        progress.stage = "import.analysis";
        progress.analysis = "unknown";
        let result = client.analyze()?;
        progress.analysis = "completed";
        result
    } else {
        progress.stage = "program.info";
        let info = client.program_info()?;
        json!({"status": "success", "program": name, "function_count": info.get("function_count"), "durable": true})
    };
    Ok(
        json!({"command": "import", "program": name, "status": "success", "data": {"analyze": analyze}}),
    )
}

fn build_oneshot_import_options(
    args: &ImportArgs,
) -> anyhow::Result<(bridge::OneShotImportOptions, bool)> {
    anyhow::ensure!(
        args.compiler_spec.is_none() || args.language.is_some(),
        "--compiler-spec requires --language"
    );
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
            program: args.program.clone(),
            loader,
            language: args.language.clone(),
            compiler_spec: args.compiler_spec.clone(),
            loader_options,
        },
        explicit_loader_control,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::protocol::{BridgeCommandError, BridgeTimeoutError};

    #[test]
    fn saved_checkpoint_keeps_underlying_path_and_recovery_selection() {
        let project = Path::new("projects/with spaces");
        let path = Path::new("data/bridge state");
        let progress = ImportProgress {
            stage: "bridge.start",
            imported: "saved",
            analysis: "completed",
            program: Some("saved-name".into()),
        };
        let error = import_failure(
            crate::error::path_io(
                "bridge.state_directory",
                path,
                std::io::Error::from(std::io::ErrorKind::PermissionDenied),
            )
            .into(),
            project,
            &progress,
        );
        let detail = crate::error::diagnostic_detail(&error);
        assert_eq!(detail["stage"], "bridge.state_directory");
        assert_eq!(detail["workflow_stage"], "bridge.start");
        assert_eq!(detail["path"], json!(path));
        assert_eq!(detail["import_status"], "saved");
        assert_eq!(
            detail["recovery"],
            json!([
                "ghidra-cli",
                "bridge",
                "start",
                "--project",
                project,
                "--program",
                "saved-name"
            ])
        );
        assert!(error.to_string().contains("Do not re-import"));
    }

    #[test]
    fn analysis_timeout_or_save_failure_never_recommends_replaying_analysis() {
        let progress = ImportProgress {
            stage: "import.analysis",
            imported: "saved",
            analysis: "unknown",
            program: Some("saved-name".into()),
        };
        let timeout = import_failure(
            BridgeTimeoutError {
                command: "analyze".into(),
                timeout_secs: 1,
            }
            .into(),
            Path::new("project"),
            &progress,
        );
        assert!(timeout.downcast_ref::<BridgeTimeoutError>().is_some());
        assert_eq!(
            crate::error::diagnostic_detail(&timeout)["recovery"],
            json!(["ghidra-cli", "job", "list", "--project", "project"])
        );
        let save = import_failure(
            BridgeCommandError {
                message: "Save failed".into(),
                detail: json!({"save_failed": true}),
            }
            .into(),
            Path::new("project"),
            &progress,
        );
        assert_eq!(
            crate::error::diagnostic_detail(&save)["recovery"][1],
            "program"
        );
        assert_eq!(
            crate::error::diagnostic_detail(&save)["recovery"][2],
            "save"
        );
    }
}
