//! Bridge client for direct communication with the Java bridge.
//!
//! Connects directly to the Java GhidraCliBridge via TCP.
//! No intermediate daemon process is needed.

use std::time::{Duration, Instant};

use anyhow::Result;
use serde_json::json;

mod annotations;
mod functions;
mod memory;
mod program;
mod scripts;
mod search;
mod transport;

/// Client for communicating with the Ghidra Java bridge.
pub struct BridgeClient {
    port: u16,
}

impl BridgeClient {
    /// Create a client for a known port.
    pub fn new(port: u16) -> Self {
        Self { port }
    }

    /// Get the port this client connects to.
    #[allow(dead_code)]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Check if bridge is responding.
    ///
    /// Uses a short read timeout so readiness polling stays snappy (a missing
    /// or unbound socket fails fast rather than blocking).
    pub fn ping(&self) -> Result<bool> {
        match self.send_command_with_timeout("ping", None, Some(Duration::from_secs(5))) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Drain accepted jobs and confirm the final save before shutdown.
    #[allow(dead_code)] // Public library API; CLI shutdown uses a shared deadline.
    pub fn shutdown(&self) -> Result<()> {
        self.send_command("shutdown_wait", None)?;
        Ok(())
    }

    /// Shutdown using the lifecycle caller's remaining total time budget.
    pub fn shutdown_with_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        self.send_command_with_deadline("shutdown_wait", None, deadline)?;
        Ok(())
    }

    /// Get bridge status.
    pub fn status(&self) -> Result<serde_json::Value> {
        self.send_command("status", None)
    }

    /// Get one job, or the full bridge job status when no ID is supplied.
    pub fn job_status(&self, job_id: Option<u64>) -> Result<serde_json::Value> {
        self.send_command("job_status", Some(json!({"job_id": job_id})))
    }

    /// Request cooperative cancellation of a job. With no ID, cancel the active job.
    pub fn cancel_job(&self, job_id: Option<u64>) -> Result<serde_json::Value> {
        self.send_command("job_cancel", Some(json!({"job_id": job_id})))
    }

    /// Get bridge info (current program, project name, program count, uptime).
    pub fn bridge_info(&self) -> Result<serde_json::Value> {
        self.send_command("bridge_info", None)
    }
}
