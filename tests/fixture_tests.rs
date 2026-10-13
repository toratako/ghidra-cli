//! Real Ghidra coverage for isolated project copies and temporary program ownership.
mod common;

#[test]
#[serial_test::serial]
fn relocated_fixture_preserves_analysis_and_isolates_mutations() -> anyhow::Result<()> {
    common::require_ghidra();
    let root = tempfile::Builder::new()
        .prefix("ghidra-copy-test-")
        .tempdir()?;
    // Exercise equivalent path spellings even on Unix.
    let first = root.path().join("first/./project");
    common::fixture::copy_analyzed_project(&first)?;
    assert!(ghidra_cli::ghidra::bridge::is_bridge_running(&first).is_none());

    let harness = common::DaemonTestHarness::new(first.to_str().unwrap(), common::FIXTURE_PROGRAM)?;
    assert_eq!(
        ghidra_cli::ghidra::bridge::is_bridge_running(&first),
        Some(harness.port())
    );
    let address = common::get_function_address(
        &harness,
        first.to_str().unwrap(),
        common::FIXTURE_PROGRAM,
        "main",
    );
    let marker = "fixture-copy-isolation-check";
    harness.client()?.comment_set(&address, marker, None)?;
    drop(harness);

    // Confirm the edit was actually persisted before checking another copy.
    let harness = common::DaemonTestHarness::new(first.to_str().unwrap(), common::FIXTURE_PROGRAM)?;
    assert!(harness
        .client()?
        .comment_get(&address)?
        .to_string()
        .contains(marker));
    drop(harness);

    // Copy after mutation and shutdown, so modifying the original source would
    // contaminate this second project and fail the assertion.
    let second = root.path().join("second/project");
    common::fixture::copy_analyzed_project(&second)?;
    let harness =
        common::DaemonTestHarness::new(second.to_str().unwrap(), common::FIXTURE_PROGRAM)?;
    let second_address = common::get_function_address(
        &harness,
        second.to_str().unwrap(),
        common::FIXTURE_PROGRAM,
        "main",
    );
    assert_eq!(address, second_address);
    assert!(!harness
        .client()?
        .comment_get(&second_address)?
        .to_string()
        .contains(marker));
    drop(harness);
    Ok(())
}

#[test]
#[serial_test::serial]
fn temporary_program_cleanup_restores_selection_and_preserves_test_panics() -> anyhow::Result<()> {
    common::require_ghidra();
    let root = tempfile::Builder::new()
        .prefix("ghidra-program-test-")
        .tempdir()?;
    let project = root.path().join("project");
    common::fixture::copy_analyzed_project(&project)?;
    let harness =
        common::DaemonTestHarness::new(project.to_str().unwrap(), common::FIXTURE_PROGRAM)?;
    let client = harness.client()?;
    let program = "temporary-fixture";
    for should_panic in [false, true] {
        client.script_run_source(
            include_str!("fixtures/runtime/CreateTemporaryProgram.java"),
            &[program.to_owned()],
            &[],
            false,
        )?;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            common::with_temporary_program(&client, program, common::FIXTURE_PROGRAM, || {
                assert_eq!(
                    client.list_programs().unwrap()["current_program_name"],
                    program
                );
                if should_panic {
                    std::panic::panic_any("fixture assertion panic");
                }
            });
        }));
        if should_panic {
            assert_eq!(
                outcome.unwrap_err().downcast_ref::<&str>(),
                Some(&"fixture assertion panic")
            );
        } else {
            outcome.unwrap();
        }
        let listed = client.list_programs()?;
        assert_eq!(listed["current_program_name"], common::FIXTURE_PROGRAM);
        assert!(listed["programs"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["name"] != program));
    }
    Ok(())
}
