//! Memory block edits, native analysis changes, and saved layout recovery.

#[macro_use]
mod common;

use common::{ensure_test_project, test_project, DaemonTestHarness};
use std::sync::OnceLock;

#[path = "memory_blocks/basic.rs"]
mod basic;
#[path = "memory_blocks/lifecycle.rs"]
mod lifecycle;

const TEST_PROGRAM: &str = common::FIXTURE_PROGRAM;
static HARNESS: OnceLock<DaemonTestHarness> = OnceLock::new();

fn harness() -> &'static DaemonTestHarness {
    HARNESS.get_or_init(|| {
        ensure_test_project(test_project(), TEST_PROGRAM);
        DaemonTestHarness::new(test_project(), TEST_PROGRAM).expect("start memory block bridge")
    })
}
