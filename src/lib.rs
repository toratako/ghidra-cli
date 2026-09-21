//! Library exports for ghidra-cli development tools and testing infrastructure.
//!
//! This module exposes the CLI definition and components needed for integration tests.

pub mod cli;

#[path = "error.rs"]
pub mod error;

#[path = "config.rs"]
pub mod config;

#[path = "ipc/mod.rs"]
pub mod ipc;

/// Re-export bridge module for integration tests.
#[path = "ghidra"]
pub mod ghidra {
    pub mod bridge;
    pub mod installation;
    pub mod java;
    #[allow(dead_code)] // Local CLI project listing/data checks are not library entry points.
    pub(crate) mod project;
}
