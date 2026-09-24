//! Bridge client for direct communication with the Java bridge.
//!
//! Connects directly to the Java GhidraCliBridge via TCP.
//! No intermediate daemon process is needed.

use std::sync::{Arc, Mutex};
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

pub use memory::MemoryBlockCreateRequest;

/// Selection observed in an executed program response, including a closed program.
#[derive(Clone, Default)]
pub(crate) struct ProgramSelection(Arc<Mutex<Option<Option<String>>>>);

impl ProgramSelection {
    #[allow(dead_code)] // The CLI consumes observations; the library only produces them.
    pub(crate) fn observed(&self) -> Option<Option<String>> {
        self.0
            .lock()
            .expect("program selection lock poisoned")
            .clone()
    }

    fn record(&self, program: Option<String>) {
        *self.0.lock().expect("program selection lock poisoned") = Some(program);
    }
}

/// Client for communicating with the Ghidra Java bridge.
pub struct BridgeClient {
    port: u16,
    program: Option<String>,
    selection: ProgramSelection,
}

impl BridgeClient {
    /// Create a client for a known port.
    pub fn new(port: u16) -> Self {
        Self {
            port,
            program: None,
            selection: ProgramSelection::default(),
        }
    }

    /// Select this program within every program request, before its operation runs.
    pub fn with_program(mut self, program: impl Into<String>) -> Self {
        self.program = Some(program.into());
        self
    }

    #[allow(dead_code)] // Shared by the binary's import/save/batch workflows.
    pub(crate) fn with_selection(mut self, selection: ProgramSelection) -> Self {
        self.selection = selection;
        self
    }

    /// Get the port this client connects to.
    #[allow(dead_code)]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Check if bridge is responding.
    ///
    /// Bounds connection retries, request writing, and response reading by
    /// one short deadline so readiness polling stays responsive.
    pub fn ping(&self) -> Result<bool> {
        self.ping_with_deadline(Instant::now() + Duration::from_secs(5))
    }

    fn ping_with_deadline(&self, deadline: Instant) -> Result<bool> {
        match self.send_command_with_deadline("ping", None, Some(deadline)) {
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
    pub fn job_status(&self, job_id: Option<&str>) -> Result<serde_json::Value> {
        self.send_command("job_status", Some(json!({"job_id": job_id})))
    }

    /// Request cooperative cancellation of a job. With no ID, cancel the active job.
    pub fn cancel_job(&self, job_id: Option<&str>) -> Result<serde_json::Value> {
        self.send_command("job_cancel", Some(json!({"job_id": job_id})))
    }

    /// Retrieve a retained response, including the original command's structured errors.
    /// Success describes retrieval; inspect the returned job state and response status.
    pub fn job_result(&self, job_id: &str) -> Result<serde_json::Value> {
        self.send_command("job_result", Some(json!({"job_id": job_id})))
    }

    /// Get bridge info (current program, project name, program count, uptime).
    pub fn bridge_info(&self) -> Result<serde_json::Value> {
        self.send_command("bridge_info", None)
    }
}
