//! Closed-project GAR workflows. The bootstrap owns Ghidra's lock through publication.

use super::{acquire_lifecycle_lock, import, shutdown_timeout, stop_bridge_then};
use crate::ghidra::installation::Installation;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub fn archive_project(
    project: &Path,
    output: &Path,
    installation: &Installation,
) -> Result<Value> {
    let mut project = std::path::absolute(project)?;
    let mut output = std::path::absolute(output)?;
    let result = (|| {
        project = resolve_parent(&project)?;
        output = resolve_parent(&output)?;
        let paths = crate::ghidra::project::ProjectPaths::new(&project)
            .context("Project must have a name")?;
        anyhow::ensure!(
            paths.descriptor.is_file() && paths.data.is_dir(),
            "Project requires both .gpr and .rep: {}",
            project.display()
        );
        anyhow::ensure!(
            !std::fs::symlink_metadata(&paths.data)?.file_type().is_symlink(),
            "Project .rep is a symbolic link; use the real project base path so Ghidra's lock protects its data"
        );
        require_absent(&output)?;
        let parent = output.parent().context("Output has no parent")?;
        anyhow::ensure!(
            !parent.starts_with(dunce::canonicalize(&paths.data)?),
            "Archive output must be outside the project's .rep directory"
        );
        stop_bridge_then(&project, shutdown_timeout(), || {
            bootstrap(&project, &output, "archive", installation)
        })
    })();
    annotate(result, &project, &output, "archive")
}

pub fn restore_project(
    archive: &Path,
    project: &Path,
    installation: &Installation,
) -> Result<Value> {
    let mut project = std::path::absolute(project)?;
    let mut archive = std::path::absolute(archive)?;
    let result = (|| {
        anyhow::ensure!(
            archive.is_file(),
            "Archive is not a file: {}",
            archive.display()
        );
        archive = dunce::canonicalize(&archive)?;
        // Resolve the destination before choosing its lifecycle lock, including
        // new parent directories that the bootstrap previously created.
        std::fs::create_dir_all(project.parent().context("Project has no parent")?)?;
        project = resolve_parent(&project)?;
        let paths = crate::ghidra::project::ProjectPaths::new(&project)
            .context("Project must have a name")?;
        require_absent(&paths.descriptor)?;
        require_absent(&paths.data)?;
        let deadline = shutdown_timeout().map(|duration| std::time::Instant::now() + duration);
        let _lock = acquire_lifecycle_lock(&project, deadline)?;
        // Ghidra's own lock in the bootstrap also protects the destination as
        // its .rep identity changes from an absent path to a real directory.
        bootstrap(&project, &archive, "restore", installation)
    })();
    annotate(result, &project, &archive, "restore")
}

fn resolve_parent(path: &Path) -> Result<PathBuf> {
    // Project bases and archive outputs need not exist. Resolve their parent
    // through the filesystem before appending the name: lexical normalization
    // of `symlink/../name` can select an entirely different project or file.
    let name = path.file_name().context("Path must have a name")?;
    let parent = path.parent().context("Path has no parent")?;
    Ok(dunce::canonicalize(parent)?.join(name))
}

fn require_absent(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(crate::error::path_io("project.archive_preflight", path, error).into()),
        Ok(_) => anyhow::bail!("Destination already exists: {}", path.display()),
    }
}

fn bootstrap(
    project: &Path,
    file: &Path,
    operation: &str,
    installation: &Installation,
) -> Result<Value> {
    let work = tempfile::Builder::new()
        .prefix("ghidra-cli-archive-")
        .tempdir()?;
    let result = import::run_bootstrap(
        &work.path().join("bootstrap"),
        installation,
        &json!({"archive_operation": operation, "project_path": project, "file": file,
            "workspace": work.path()}),
        None,
    );
    let path: PathBuf = work.path().to_owned();
    if let Err(cleanup) = work.close() {
        let mut detail = result
            .as_ref()
            .err()
            .map(crate::error::diagnostic_detail)
            .unwrap_or_else(|| json!({}));
        if !detail["remaining_paths"].is_array() {
            detail["remaining_paths"] = json!([]);
        }
        detail["remaining_paths"]
            .as_array_mut()
            .unwrap()
            .push(json!(path));
        detail["cleanup_error"] = json!(cleanup.to_string());
        if let Ok(value) = &result {
            detail["completion"] = value.clone();
        }
        let message = match &result {
            Ok(_) => "GAR operation completed but bootstrap cleanup failed".to_owned(),
            Err(error) => format!("{error:#}; bootstrap cleanup failed: {cleanup}"),
        };
        let context = crate::ipc::protocol::BridgeCommandError { message, detail };
        return match result {
            Err(error) => Err(error.context(context)),
            Ok(_) => Err(context.into()),
        };
    }
    result
}

fn annotate(result: Result<Value>, project: &Path, file: &Path, operation: &str) -> Result<Value> {
    result.map_err(|error| {
        let mut detail = crate::error::diagnostic_detail(&error);
        detail["operation"] = json!(operation);
        detail["project_path"] = json!(project);
        detail[if operation == "archive" {
            "output"
        } else {
            "archive"
        }] = json!(file);
        detail["bridge_state"] = json!(match super::read_pid_file(project) {
            Ok(Some(pid)) if super::is_pid_alive(pid) => "running",
            Ok(_) => "stopped",
            Err(_) => "unknown",
        });
        let message = format!("{error:#}");
        error.context(crate::ipc::protocol::BridgeCommandError { message, detail })
    })
}
