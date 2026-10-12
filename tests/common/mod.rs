//! Common test utilities for E2E tests.
//!
//! This module provides:
//! - `schemas`: Typed data structures for JSON output validation
//! - `helpers`: Fluent test helpers and utilities
//! - `DaemonTestHarness`: Bridge lifecycle management for tests

#![allow(dead_code, unused_imports)]

mod bridge;
#[macro_use]
mod doctor;
pub mod fixture;
pub mod helpers;
mod process;
pub mod schemas;

// Re-export commonly used items
pub use bridge::{with_temporary_program, DaemonTestHarness};
pub use doctor::{assert_doctor_ready, require_ghidra, DoctorCheck};
pub use helpers::{
    get_function_address, get_function_addresses, ghidra, GhidraCommand, GhidraResult,
};
pub use process::{run_cli_with_timeout, run_command_with_output};
pub use schemas::Validate;

use std::path::PathBuf;
use std::sync::{Once, OnceLock};

/// Fresh Ghidra imports use the fixture's filename as their program name.
pub const FIXTURE_PROGRAM: &str = if cfg!(windows) {
    "sample_binary.exe"
} else {
    "sample_binary"
};

pub use fixture::fixture_binary;

static PROJECT: OnceLock<(tempfile::TempDir, PathBuf)> = OnceLock::new();

fn register_cleanup() {
    static REGISTER: Once = Once::new();
    REGISTER.call_once(|| {
        // SAFETY: The callback has C ABI, remains valid for the process lifetime,
        // and catches panics so none can unwind across the FFI boundary.
        assert_eq!(
            unsafe { libc::atexit(cleanup_suite) },
            0,
            "Cannot register suite cleanup"
        );
    });
}

extern "C" fn cleanup_suite() {
    let _ = std::panic::catch_unwind(|| {
        if let Some((directory, project)) = PROJECT.get() {
            // Rust statics are not dropped. Explicitly stop the suite's bridge
            // before removing its unique project, including on test failures.
            if ghidra_cli::ghidra::bridge::stop_bridge(project).is_ok() {
                let _ = std::fs::remove_file(project.with_extension("gpr"));
                let _ = std::fs::remove_dir_all(project.with_extension("rep"));
                let _ = std::fs::remove_dir_all(directory.path());
            }
        }
        fixture::cleanup();
    });
}

/// Each suite opens its own copy under a unique directory. Keep the source's
/// project basename so relocation does not require editing Ghidra metadata.
pub fn test_project() -> &'static str {
    register_cleanup();
    PROJECT
        .get_or_init(|| {
            let root = ghidra_cli::config::Config::load()
                .and_then(|config| config.get_project_dir())
                .expect("Could not determine project dir");
            std::fs::create_dir_all(&root).expect("Failed to create project directory");
            let root = dunce::canonicalize(root).expect("Failed to resolve project directory");
            let dir = tempfile::Builder::new()
                .prefix("ghidra-test-")
                .tempdir_in(root)
                .expect("Failed to create suite project directory");
            let project = dir.path().join(fixture::PROJECT_NAME);
            (dir, project)
        })
        .1
        .to_str()
        .expect("Test project path is not UTF-8")
}

/// Copy the run's closed, analyzed fixture once for this suite.
pub fn ensure_test_project(project: &str, program: &str) {
    static SETUP: OnceLock<std::result::Result<(), String>> = OnceLock::new();
    assert_eq!(
        project,
        test_project(),
        "Setup must use the suite's project"
    );
    assert_eq!(
        program, FIXTURE_PROGRAM,
        "Setup must use the fixture program"
    );
    require_ghidra();
    let setup = SETUP.get_or_init(|| {
        fixture::copy_analyzed_project(std::path::Path::new(project))
            .map_err(|error| format!("{error:#}"))
    });
    if let Err(error) = setup {
        panic!("Failed to prepare test project: {error}");
    }
}
