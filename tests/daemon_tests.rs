//! Bridge lifecycle, program ownership, persistence, and control-plane tests.
//! Each test owns its harness; all modules share the suite's fixture and serial lock.

#[macro_use]
mod common;
use common::{test_project, DaemonTestHarness};

#[path = "daemon/decompiler.rs"]
mod decompiler;
#[path = "daemon/deletion.rs"]
mod deletion;
#[path = "daemon/jobs.rs"]
mod jobs;
#[path = "daemon/lifecycle.rs"]
mod lifecycle;
#[path = "daemon/output.rs"]
mod output;
#[path = "daemon/program_session.rs"]
mod program_session;
#[path = "daemon/transaction.rs"]
mod transaction;

const TEST_PROGRAM: &str = common::FIXTURE_PROGRAM;

/// Start the bridge; missing programs and startup failures must fail the test.
fn start_daemon() -> DaemonTestHarness {
    DaemonTestHarness::new(test_project(), TEST_PROGRAM)
        .unwrap_or_else(|e| panic!("Failed to start bridge: {e}"))
}
