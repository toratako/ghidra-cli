//! Short-lived headless workflows, completed before the persistent bridge opens a project.

use super::headless::headless_command;
use super::{sources, startup};
use crate::ghidra::installation::Installation;
use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::Stdio;
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

/// Load with the requested name/options, analyze, save, release, and exit before
/// returning the actual saved name. A private JSON receipt confirms script success;
/// a zero headless exit status alone does not establish that the script succeeded.
pub fn import_oneshot(
    project_path: &Path,
    binary_path: &Path,
    installation: &Installation,
    options: &OneShotImportOptions,
) -> Result<String> {
    let mut args = serde_json::to_value(options)?;
    args["binary_path"] = json!(binary_path);
    let result = run_bootstrap(project_path, installation, &args, None)?;
    result["program"]
        .as_str()
        .map(str::to_owned)
        .context("Import receipt did not contain the saved program name")
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
            for line in BufReader::new(stream).lines().map_while(Result::ok) {
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
    if waited.is_err() {
        startup::kill_process_tree(&mut child);
    }
    let diagnostics = format!(
        "{}\n{}",
        stdout.join().unwrap_or_default(),
        stderr.join().unwrap_or_default()
    );
    let status = waited.with_context(|| format!("Ghidra bootstrap output: {diagnostics}"))?;
    anyhow::ensure!(
        status.success(),
        "Ghidra bootstrap failed (exit {:?}): {}",
        status.code(),
        diagnostics
    );
    let receipt_bytes = std::fs::read(&receipt)
        .map_err(|e| crate::error::path_io("import.receipt_read", &receipt, e))
        .with_context(|| {
            format!("Ghidra bootstrap did not produce its completion receipt: {diagnostics}")
        })?;
    let result: Value = serde_json::from_slice(&receipt_bytes)
        .with_context(|| format!("Invalid bootstrap receipt at {}", receipt.display()))?;
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
