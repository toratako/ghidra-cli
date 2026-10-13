use super::{start_daemon, TEST_PROGRAM};
use crate::common::{ensure_test_project, test_project};
use serial_test::serial;

// Use a separate saved Program and the real dispatcher, as in transaction.rs.
// Native callbacks and request monitors inject cancellation/timeout without
// timing a large function or adding production failure hooks.
const DECOMPILER_PROBE: &str = include_str!("../fixtures/daemon/DecompilerSessionProbe.java");

#[test]
#[serial]
fn test_decompiler_reuse_invalidation_and_recovery() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().unwrap();
    let function = crate::common::helpers::get_fixture_function(&client, "add_numbers");
    let other = crate::common::helpers::get_fixture_function(&client, "multiply");
    let result = client
        .script_run_source(
            DECOMPILER_PROBE,
            &[
                format!("decompiler-{}", uuid::Uuid::new_v4()),
                function.address,
                other.address,
            ],
            &[],
            false,
        )
        .unwrap();
    assert!(
        result["stdout"]
            .as_str()
            .unwrap()
            .contains("decompiler-session-ok"),
        "{result}"
    );
}
