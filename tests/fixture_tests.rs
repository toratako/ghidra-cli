//! Real Ghidra coverage for relocating a closed project and isolating copies.
mod common;

#[test]
fn relocated_fixture_preserves_analysis_and_isolates_mutations() -> anyhow::Result<()> {
    common::require_ghidra();
    let root = tempfile::Builder::new()
        .prefix("ghidra-copy-test-")
        .tempdir()?;
    let first = root.path().join("first/project");
    common::fixture::copy_analyzed_project(&first)?;
    assert!(ghidra_cli::ghidra::bridge::is_bridge_running(&first).is_none());

    let harness = common::DaemonTestHarness::new(first.to_str().unwrap(), common::FIXTURE_PROGRAM)?;
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
