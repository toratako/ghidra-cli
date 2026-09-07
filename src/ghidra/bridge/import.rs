//! Durable one-shot headless import, completed before a persistent bridge opens the project.

use super::{apply_java_home, find_headless_script};
use anyhow::{Context, Result};
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Command, Stdio};
use tracing::info;

#[derive(Debug, Clone, Default)]
pub struct OneShotImportOptions {
    pub analyze: bool,
    pub loader: Option<String>,
    pub language: Option<String>,
    pub compiler_spec: Option<String>,
    pub loader_options: Vec<(String, String)>,
}

fn append_import_options(cmd: &mut Command, options: &OneShotImportOptions) {
    if !options.analyze {
        cmd.arg("-noanalysis");
    }
    if let Some(language) = &options.language {
        cmd.arg("-processor").arg(language);
    }
    if let Some(cspec) = &options.compiler_spec {
        cmd.arg("-cspec").arg(cspec);
    }
    if let Some(loader) = &options.loader {
        cmd.arg("-loader").arg(loader);
    }
    for (name, value) in &options.loader_options {
        cmd.arg(format!("-loader-{}", name)).arg(value);
    }
}

/// Import a binary into the project using a clean, short-lived `analyzeHeadless
/// -import` run (no long-lived preScript), then return the imported program's
/// name.
///
/// This is the durable way to create a brand-new project. Unlike bootstrapping
/// the persistent bridge with `-import` (which holds the imported program inside
/// HeadlessAnalyzer's transaction for the bridge's whole life and only commits
/// it during teardown — a commit we then race by killing the JVM), this run
/// imports, optionally analyzes, saves, commits the project, and exits on its
/// own. The persistent bridge can then open the already-committed program in
/// `-process` mode, where saves are durable and no teardown commit is required.
pub fn import_oneshot(
    project_path: &Path,
    binary_path: &Path,
    ghidra_install_dir: &Path,
    options: &OneShotImportOptions,
) -> Result<String> {
    info!("Importing binary into new project (one-shot)...");

    let headless_script = find_headless_script(ghidra_install_dir)?;

    let ghidra_project_dir = project_path.parent().unwrap_or(project_path);
    let ghidra_project_name = project_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "project".to_string());

    // HeadlessAnalyzer names the imported program after the binary's filename;
    // `-import` has no rename option, so that is the program's domain name.
    let program_name = binary_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .ok_or_else(|| anyhow::anyhow!("Binary path has no filename: {}", binary_path.display()))?;

    let mut cmd = Command::new(&headless_script);
    cmd.arg(ghidra_project_dir)
        .arg(&ghidra_project_name)
        .arg("-import")
        .arg(binary_path);
    append_import_options(&mut cmd, options);
    cmd.arg("-overwrite");

    apply_java_home(&mut cmd, ghidra_install_dir);

    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // Own process group so the whole JVM tree is killable as a unit (parity with
    // start_bridge), avoiding orphaned JVMs holding pipes open.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        cmd.creation_flags(CREATE_NEW_PROCESS_GROUP);
    }

    info!("Ghidra one-shot import command: {:?}", cmd);
    let mut child = cmd
        .spawn()
        .context("Failed to spawn Ghidra headless import")?;

    // Drain stdout/stderr on threads so the pipes never fill (which would stall
    // the JVM), logging each line and watching for the success/failure markers.
    let stdout = child.stdout.take().expect("stdout should be piped");
    let stdout_handle = std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        let mut saw_success = false;
        for line in reader.lines().map_while(Result::ok) {
            info!("[Ghidra import stdout] {}", line);
            if line.contains("Import succeeded") || line.contains("REPORT: Save succeeded") {
                saw_success = true;
            }
        }
        saw_success
    });
    let stderr = child.stderr.take().expect("stderr should be piped");
    let stderr_handle = std::thread::spawn(move || {
        let reader = BufReader::new(stderr);
        let mut last_error = String::new();
        for line in reader.lines().map_while(Result::ok) {
            info!("[Ghidra import stderr] {}", line);
            if line.contains("ERROR") || line.contains("Exception") || line.contains("Abort") {
                last_error = line.clone();
            }
        }
        last_error
    });

    let status = child
        .wait()
        .context("Failed to wait for Ghidra headless import")?;

    let saw_success = stdout_handle.join().unwrap_or(false);
    let last_error = stderr_handle.join().unwrap_or_default();

    if !status.success() {
        anyhow::bail!(
            "Ghidra import failed (exit {:?}){}",
            status.code(),
            if last_error.is_empty() {
                String::new()
            } else {
                format!(": {}", last_error)
            }
        );
    }
    if !saw_success {
        anyhow::bail!(
            "Ghidra import did not report success{}",
            if last_error.is_empty() {
                String::new()
            } else {
                format!(": {}", last_error)
            }
        );
    }

    info!("One-shot import complete: {}", program_name);
    Ok(program_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_import_options_map_to_headless_arguments() {
        let mut cmd = Command::new("analyzeHeadless");
        let options = OneShotImportOptions {
            analyze: false,
            loader: Some("BinaryLoader".to_string()),
            language: Some("x86:LE:32:default".to_string()),
            compiler_spec: Some("default".to_string()),
            loader_options: vec![
                ("baseAddr".to_string(), "0x8000".to_string()),
                ("blockName".to_string(), "ROM".to_string()),
            ],
        };
        append_import_options(&mut cmd, &options);
        let args: Vec<String> = cmd
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect();
        assert_eq!(
            args,
            vec![
                "-noanalysis",
                "-processor",
                "x86:LE:32:default",
                "-cspec",
                "default",
                "-loader",
                "BinaryLoader",
                "-loader-baseAddr",
                "0x8000",
                "-loader-blockName",
                "ROM",
            ]
        );
    }
}
