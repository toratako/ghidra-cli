//! Run-scoped fixture source; every suite opens its own ordinary file copies.

use anyhow::{ensure, Context, Result};
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Instant;

pub const RUN_DIR_ENV: &str = "GHIDRA_TEST_RUN_DIR";
pub const PROJECT_NAME: &str = "project";

struct Storage {
    path: PathBuf,
    owned: Option<tempfile::TempDir>,
}

static STORAGE: OnceLock<Storage> = OnceLock::new();

fn storage() -> &'static Path {
    &STORAGE
        .get_or_init(|| {
            super::register_cleanup();
            if let Some(path) = std::env::var_os(RUN_DIR_ENV) {
                let path = dunce::canonicalize(path).expect("Test run directory must exist");
                assert!(path.is_dir(), "Test run path must be a directory");
                Storage { path, owned: None }
            } else {
                let dir = tempfile::Builder::new()
                    .prefix("ghidra-fixture-")
                    .tempdir()
                    .expect("Failed to create fixture directory");
                Storage {
                    path: dir.path().to_path_buf(),
                    owned: Some(dir),
                }
            }
        })
        .path
}

pub(super) fn cleanup() {
    if let Some(Storage {
        owned: Some(dir), ..
    }) = STORAGE.get()
    {
        let _ = fs::remove_dir_all(dir.path());
    }
}

/// Publish only a fully prepared directory. File locks also serialize separate
/// test processes and are released by the OS if a builder is terminated.
pub fn publish_once(
    root: &Path,
    name: &str,
    build: impl FnOnce(&Path) -> Result<()>,
) -> Result<PathBuf> {
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(root.join(format!("{name}.lock")))?;
    lock.lock().context("Failed to lock test fixture")?;
    let destination = root.join(name);
    if destination.is_dir() {
        return Ok(destination);
    }
    let failed = root.join(format!("{name}.failed"));
    if failed.exists() {
        anyhow::bail!(
            "Earlier {name} setup failed in this run:\n{}",
            fs::read_to_string(failed)?
        );
    }
    // Ghidra rejects project paths with any component starting with '.'.
    let staging = tempfile::Builder::new()
        .prefix("preparing-")
        .tempdir_in(root)?;
    let started = Instant::now();
    if let Err(error) = build(staging.path()) {
        fs::write(failed, format!("{error:#}"))?;
        return Err(error);
    }
    fs::rename(staging.path(), &destination)?;
    eprintln!(
        "[test setup] {name}: {:.2}s",
        started.elapsed().as_secs_f64()
    );
    Ok(destination)
}

/// Compile once per runner invocation, or once per executable with cargo test.
pub fn fixture_binary() -> PathBuf {
    publish_once(storage(), "binary", |dir| {
        let output = std::process::Command::new("rustc")
            .args(["--edition", "2021", "-C", "strip=debuginfo"])
            .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sample_binary.rs"))
            .arg("-o")
            .arg(dir.join(super::FIXTURE_PROGRAM))
            .output()
            .context("Failed to run rustc for test fixture")?;
        ensure!(
            output.status.success(),
            "Fixture compilation failed: {}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    })
    .expect("Failed to build fixture")
    .join(super::FIXTURE_PROGRAM)
}

pub fn copy_analyzed_project(destination: &Path) -> Result<()> {
    let binary = fixture_binary();
    let source = publish_once(storage(), "analyzed", |dir| {
        use ghidra_cli::ghidra::bridge::{import_oneshot, OneShotImportOptions};
        let config = ghidra_cli::config::Config::load()?;
        let program = import_oneshot(
            &dir.join(PROJECT_NAME),
            &binary,
            &config.get_ghidra_installation()?,
            &OneShotImportOptions {
                analyze: true,
                ..Default::default()
            },
        )?;
        ensure!(
            program == super::FIXTURE_PROGRAM,
            "Unexpected fixture program: {program}"
        );
        // import_oneshot waits for Ghidra to save and exit. Never open the
        // published source in a bridge; all subsequent use goes through copies.
        ensure!(dir.join("project.gpr").is_file(), "Missing fixture project");
        ensure!(
            dir.join("project.rep").is_dir(),
            "Missing fixture repository"
        );
        Ok(())
    })?;
    let started = Instant::now();
    copy_project(&source.join(PROJECT_NAME), destination)?;
    eprintln!(
        "[test setup] project copy: {:.2}s",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

/// The source must be closed. Preserve its basename and copy only the saved
/// project files, excluding sibling lock/discovery files and builder metadata.
pub fn copy_project(source: &Path, destination: &Path) -> Result<()> {
    ensure!(
        source.file_name() == destination.file_name(),
        "Project basenames must match"
    );
    let parent = destination
        .parent()
        .context("Project needs a parent directory")?;
    fs::create_dir_all(parent)?;
    let gpr = destination.with_extension("gpr");
    let rep = destination.with_extension("rep");
    ensure!(
        !gpr.exists() && !rep.exists(),
        "Refusing to overwrite a test project"
    );
    let staging = tempfile::Builder::new()
        .prefix(".copying-")
        .tempdir_in(parent)?;
    let staged_rep = staging.path().join("project.rep");
    for entry in walkdir::WalkDir::new(source.with_extension("rep")) {
        let entry = entry?;
        let relative = entry.path().strip_prefix(source.with_extension("rep"))?;
        let target = staged_rep.join(relative);
        if entry.file_type().is_dir() {
            fs::create_dir_all(target)?;
        } else {
            ensure!(
                entry.file_type().is_file(),
                "Unexpected fixture entry: {}",
                entry.path().display()
            );
            fs::copy(entry.path(), target)?;
        }
    }
    fs::copy(
        source.with_extension("gpr"),
        staging.path().join("project.gpr"),
    )?;
    fs::rename(staged_rep, &rep)?;
    if let Err(error) = fs::rename(staging.path().join("project.gpr"), gpr) {
        let _ = fs::remove_dir_all(rep);
        return Err(error.into());
    }
    Ok(())
}
