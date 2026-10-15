//! Short-lived headless workflows, completed before the persistent bridge opens a project.

use super::headless::headless_command;
use super::{sources, startup};
use crate::ghidra::installation::Installation;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tracing::info;

#[derive(Debug, Clone, Default, Serialize)]
pub struct OneShotImportOptions {
    pub analyze: bool,
    pub program: Option<String>,
    pub loader: Option<String>,
    pub language: Option<String>,
    pub compiler_spec: Option<String>,
    pub loader_options: Vec<(String, String)>,
}

/// Bounded rendering of the loader's MessageLog. Character counts are UTF-16
/// code units and describe the rendered log, which Ghidra may already clip.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct LoaderDiagnostics {
    pub text: String,
    pub truncated: bool,
    pub retained_characters: usize,
    pub original_characters: usize,
    pub maximum_characters: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OneShotImportReceipt {
    pub status: String,
    pub program: String,
    pub program_path: String,
    pub import_status: String,
    pub analysis_status: String,
    pub loader_diagnostics: LoaderDiagnostics,
}

/// Load with the requested name/options, analyze, save, release, and exit before
/// returning the saved program and loader diagnostics. A private JSON receipt confirms script success;
/// a zero headless exit status alone does not establish that the script succeeded.
pub fn import_oneshot(
    project_path: &Path,
    binary_path: &Path,
    installation: &Installation,
    options: &OneShotImportOptions,
) -> Result<OneShotImportReceipt> {
    let mut args = serde_json::to_value(options)?;
    args["binary_path"] = json!(binary_path);
    let result = run_bootstrap(project_path, installation, &args, None)?;
    serde_json::from_value(result).context("Invalid import completion receipt")
}

pub(super) fn run_bootstrap(
    project_path: &Path,
    installation: &Installation,
    args: &Value,
    timeout: Option<Duration>,
) -> Result<Value> {
    let project_path = std::path::absolute(project_path)?;
    let scripts = sources::install()?;
    let work = tempfile::tempdir().map_err(|e| {
        crate::error::path_io("import.temporary_directory", &std::env::temp_dir(), e)
    })?;
    let request = work.path().join("request.json");
    let receipt = work.path().join("receipt.json");
    std::fs::write(&request, serde_json::to_vec(args)?)
        .map_err(|e| crate::error::path_io("import.request_write", &request, e))?;
    let directory = project_path
        .parent()
        .context("Project has no parent directory")?;
    std::fs::create_dir_all(directory)
        .map_err(|e| crate::error::path_io("import.project_directory", directory, e))?;
    let arguments = [
        directory.as_os_str().to_owned(),
        project_path
            .file_name()
            .context("Project has no name")?
            .to_owned(),
        "-noanalysis".into(),
        "-scriptPath".into(),
        scripts.into_os_string(),
        "-preScript".into(),
        "GhidraCliBootstrap.java".into(),
        request.as_os_str().to_owned(),
        receipt.as_os_str().to_owned(),
    ];
    let mut cmd = headless_command(installation, &arguments)?;
    execute_bootstrap(&mut cmd, &receipt, timeout)
}

fn execute_bootstrap(
    cmd: &mut Command,
    receipt: &Path,
    timeout: Option<Duration>,
) -> Result<Value> {
    let executable = std::path::PathBuf::from(cmd.get_program());
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0000_0200);
    }
    info!("Ghidra bootstrap command: {:?}", cmd);
    let mut child = cmd
        .spawn()
        .map_err(|e| crate::error::path_io("import.launch", &executable, e))?;
    fn drain(stream: impl std::io::Read + Send + 'static) -> std::thread::JoinHandle<String> {
        std::thread::spawn(move || {
            let mut tail = std::collections::VecDeque::new();
            for line in startup::output_lines(stream) {
                info!("[Ghidra bootstrap] {line}");
                if tail.len() == 30 {
                    tail.pop_front();
                }
                tail.push_back(line);
            }
            tail.into_iter().collect::<Vec<_>>().join("\n")
        })
    }
    let stdout = drain(child.stdout.take().unwrap());
    let stderr = drain(child.stderr.take().unwrap());
    let began = Instant::now();
    let waited = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Err(error) => break Err(anyhow::Error::new(error).context("import.wait failed")),
            Ok(None) => {}
        }
        if timeout.is_some_and(|limit| began.elapsed() >= limit) {
            break Err(anyhow::anyhow!(
                "Ghidra bootstrap did not finish within {}s",
                began.elapsed().as_secs()
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    // A finished one-shot launcher can leave descendants holding the inherited
    // pipes, even on successful exit. Close the group before joining readers.
    startup::kill_process_tree(&mut child);
    let diagnostics = format!(
        "{}\n{}",
        stdout.join().unwrap_or_default(),
        stderr.join().unwrap_or_default()
    );
    let process_result = waited
        .with_context(|| format!("Ghidra bootstrap output: {diagnostics}"))
        .and_then(|status| {
            anyhow::ensure!(
                status.success(),
                "Ghidra bootstrap failed (exit {:?}): {}",
                status.code(),
                diagnostics
            );
            Ok(())
        });
    let receipt_result = (|| {
        let receipt_bytes = std::fs::read(receipt)
            .map_err(|e| crate::error::path_io("import.receipt_read", receipt, e))
            .with_context(|| {
                format!("Ghidra bootstrap did not produce its completion receipt: {diagnostics}")
            })?;
        let result: Value = serde_json::from_slice(&receipt_bytes)
            .with_context(|| format!("Invalid bootstrap receipt at {}", receipt.display()))?;
        bootstrap_result(result)
    })();
    match process_result {
        Ok(()) => receipt_result,
        Err(error) => {
            // The script writes its receipt before headless shutdown. A later
            // process failure must not erase a saved import or published GAR.
            let (message, detail) = match receipt_result {
                Ok(completion) => {
                    let mut detail = completion.clone();
                    detail.as_object_mut().unwrap().remove("status");
                    detail["completion"] = completion;
                    (format!("{error:#}"), detail)
                }
                Err(receipt_error) => {
                    let Some(failure) =
                        receipt_error.downcast_ref::<crate::ipc::protocol::BridgeCommandError>()
                    else {
                        return Err(error);
                    };
                    (
                        format!("{error:#}; script failed: {receipt_error:#}"),
                        failure.detail.clone(),
                    )
                }
            };
            Err(error.context(crate::ipc::protocol::BridgeCommandError { message, detail }))
        }
    }
}

fn bootstrap_result(result: Value) -> Result<Value> {
    if result["status"] != "success" {
        return Err(crate::ipc::protocol::BridgeCommandError {
            message: result["message"]
                .as_str()
                .unwrap_or("Ghidra bootstrap failed")
                .to_owned(),
            detail: result.get("detail").cloned().unwrap_or_else(|| json!({})),
        }
        .into());
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn encoded_launcher_output_keeps_later_failure_diagnostics() {
        let work = tempfile::tempdir().unwrap();
        let receipt = work.path().join("receipt.json");
        let completion = json!({
            "status": "success", "program": "saved-name", "import_status": "saved"
        });
        std::fs::write(&receipt, serde_json::to_vec(&completion).unwrap()).unwrap();
        let error = execute_bootstrap(
            Command::new("sh")
                .arg("-c")
                .arg("printf '\\351\\nfinal bootstrap diagnostic\\n' >&2; exit 7"),
            &receipt,
            None,
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("final bootstrap diagnostic"),
            "{error:#}"
        );
        assert_eq!(
            crate::error::diagnostic_detail(&error)["completion"],
            completion
        );
    }

    #[cfg(unix)]
    #[test]
    fn launcher_exit_closes_descendant_pipes_and_keeps_completion() {
        let work = tempfile::tempdir().unwrap();
        let receipt = work.path().join("receipt.json");
        let completion = json!({
            "status": "success", "program": "saved-name", "program_path": "/saved-name",
            "import_status": "saved", "analysis_status": "completed",
            "loader_diagnostics": {"text": "loader evidence", "truncated": false,
                "retained_characters": 15, "original_characters": 15, "maximum_characters": 16384}
        });
        std::fs::write(&receipt, serde_json::to_vec(&completion).unwrap()).unwrap();
        for exit in [0, 7] {
            let began = Instant::now();
            let result = execute_bootstrap(
                Command::new("sh").arg("-c").arg(format!(
                    "sleep 3 & printf 'launcher cleanup failed\\n' >&2; exit {exit}"
                )),
                &receipt,
                Some(Duration::from_millis(100)),
            );
            assert!(began.elapsed() < Duration::from_secs(2), "{result:?}");
            if exit == 0 {
                assert_eq!(result.unwrap(), completion);
            } else {
                let error = result.unwrap_err();
                assert!(format!("{error:#}").contains("launcher cleanup failed"));
                let detail = crate::error::diagnostic_detail(&error);
                assert_eq!(detail["import_status"], "saved");
                assert_eq!(detail["analysis_status"], "completed");
                assert_eq!(detail["program"], "saved-name");
                assert_eq!(detail["loader_diagnostics"]["text"], "loader evidence");
                assert_eq!(detail["completion"], completion);
            }
        }
    }

    #[test]
    fn failed_launcher_keeps_the_script_failure_checkpoint() {
        let work = tempfile::tempdir().unwrap();
        let receipt = work.path().join("receipt.json");
        let checkpoint = json!({
            "stage": "import.save", "import_status": "unknown", "analysis_status": "completed",
            "loader_diagnostics": {"text": "save evidence", "truncated": false,
                "retained_characters": 13, "original_characters": 13, "maximum_characters": 16384}
        });
        std::fs::write(
            &receipt,
            serde_json::to_vec(&json!({
                "status": "error", "message": "program save failed", "detail": checkpoint
            }))
            .unwrap(),
        )
        .unwrap();
        #[cfg(unix)]
        let mut command = {
            let mut command = Command::new("sh");
            command.args(["-c", "exit 7"]);
            command
        };
        #[cfg(windows)]
        let mut command = {
            let mut command = Command::new("cmd");
            command.args(["/C", "exit /B 7"]);
            command
        };
        let error = execute_bootstrap(&mut command, &receipt, None).unwrap_err();
        assert!(format!("{error:#}").contains("program save failed"));
        assert_eq!(crate::error::diagnostic_detail(&error), checkpoint);
    }

    #[test]
    fn bootstrap_receipts_keep_loader_diagnostics_on_success_and_failure() {
        let diagnostics = json!({
            "text": "loader 🚀\n", "truncated": false, "retained_characters": 10,
            "original_characters": 10, "maximum_characters": 16384
        });
        let success = json!({
            "status": "success", "program": "saved-name", "program_path": "/saved-name",
            "import_status": "saved", "analysis_status": "completed",
            "loader_diagnostics": diagnostics
        });
        let receipt: OneShotImportReceipt =
            serde_json::from_value(bootstrap_result(success.clone()).unwrap()).unwrap();
        assert_eq!(serde_json::to_value(receipt).unwrap(), success);
        let detail = json!({
            "stage": "import.save", "import_status": "unknown", "analysis_status": "completed",
            "loader_diagnostics": diagnostics
        });
        let error = bootstrap_result(
            json!({"status": "error", "message": "save failed", "detail": detail}),
        )
        .unwrap_err();
        let failure = error
            .downcast_ref::<crate::ipc::protocol::BridgeCommandError>()
            .unwrap();
        assert_eq!(failure.message, "save failed");
        assert_eq!(failure.detail, detail);
    }
}
