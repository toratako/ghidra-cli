//! Bridge lifecycle, program ownership, persistence, and control-plane tests.
//! Each test owns its harness; all modules share the suite's fixture and serial lock.

#[path = "support/json.rs"]
mod json_output;

#[macro_use]
mod common;
use common::{test_project, DaemonTestHarness};

#[path = "daemon/analysis.rs"]
mod analysis;
#[path = "daemon/analysis_modes.rs"]
mod analysis_modes;
#[path = "daemon/context.rs"]
mod context;
#[path = "daemon/decompiler.rs"]
mod decompiler;
#[path = "daemon/deletion.rs"]
mod deletion;
#[path = "daemon/job_results.rs"]
mod job_results;
#[path = "daemon/jobs.rs"]
mod jobs;
#[path = "daemon/lifecycle.rs"]
mod lifecycle;
#[path = "daemon/output.rs"]
mod output;
#[path = "daemon/program_session.rs"]
mod program_session;
#[path = "daemon/rebase.rs"]
mod rebase;
#[path = "daemon/transaction.rs"]
mod transaction;

const TEST_PROGRAM: &str = common::FIXTURE_PROGRAM;

/// Start the bridge; missing programs and startup failures must fail the test.
fn start_daemon() -> DaemonTestHarness {
    DaemonTestHarness::new(test_project(), TEST_PROGRAM)
        .unwrap_or_else(|e| panic!("Failed to start bridge: {e}"))
}
