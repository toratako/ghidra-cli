//! Tests for symbol operations.

use predicates::prelude::*;
use serial_test::serial;
use std::sync::OnceLock;

#[macro_use]
mod common;
use common::helpers::ghidra;
use common::{
    ensure_test_project, get_function_address, get_function_addresses, DaemonTestHarness,
};

use common::test_project;
const TEST_PROGRAM: &str = common::FIXTURE_PROGRAM;

static HARNESS: OnceLock<DaemonTestHarness> = OnceLock::new();

fn harness() -> &'static DaemonTestHarness {
    HARNESS.get_or_init(|| {
        ensure_test_project(test_project(), TEST_PROGRAM);
        DaemonTestHarness::new(test_project(), TEST_PROGRAM).expect("Failed to start daemon")
    })
}

#[test]
#[serial]
fn test_symbol_list() {
    require_ghidra!();
    let _harness = harness();

    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("symbol")
        .arg("list")
        .arg("--project")
        .arg(test_project())
        .arg("--program")
        .arg(TEST_PROGRAM)
        .output()
        .expect("Failed to run command");

    assert!(output.status.success(), "symbol list should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Known functions should appear as symbols
    // On macOS, names may have underscore prefix
    assert!(
        stdout.contains("main") || stdout.contains("_main"),
        "symbol list should contain main. Output: {}",
        stdout
    );
}

#[test]
#[serial]
fn test_symbol_create_and_get() {
    require_ghidra!();
    let harness = harness();

    let addr = get_function_address(harness, test_project(), TEST_PROGRAM, "main");

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("symbol")
        .arg("create")
        .arg(&addr)
        .arg("test_symbol")
        .arg("--project")
        .arg(test_project())
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("symbol")
        .arg("get")
        .arg("test_symbol")
        .arg("--project")
        .arg(test_project())
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains("test_symbol"));
}

#[test]
#[serial]
fn test_symbol_rename() {
    require_ghidra!();
    let harness = harness();

    let addrs = get_function_addresses(harness, test_project(), TEST_PROGRAM, 2);
    let addr = &addrs[1];

    // Use unique names to avoid collisions with cached project state
    let old_name = format!("old_sym_{}", std::process::id());
    let new_name = format!("new_sym_{}", std::process::id());

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("symbol")
        .arg("create")
        .arg(addr)
        .arg(&old_name)
        .arg("--project")
        .arg(test_project())
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("symbol")
        .arg("rename")
        .arg(&old_name)
        .arg(&new_name)
        .arg("--project")
        .arg(test_project())
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    // Verify new symbol exists
    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("symbol")
        .arg("get")
        .arg(&new_name)
        .arg("--project")
        .arg(test_project())
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains(&*new_name));
}

#[test]
#[serial]
fn test_symbol_get_nonexistent() {
    require_ghidra!();
    let _harness = harness();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("symbol")
        .arg("get")
        .arg("nonexistent_symbol_12345")
        .arg("--project")
        .arg(test_project())
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .failure();
}

#[test]
#[serial]
fn test_hex_symbol_names_can_be_read_renamed_and_deleted() {
    require_ghidra!();
    let harness = harness();
    let client = harness.client().unwrap();
    let address = get_function_address(harness, test_project(), TEST_PROGRAM, "main");

    for (name, renamed) in [
        ("dead", "beef"),
        ("12345", "67890"),
        ("0xdead", "0xbeef"),
        ("0Xdead", "0Xbeef"),
    ] {
        ghidra(harness)
            .args(["symbol", "create", &address, name])
            .run()
            .assert_success();
        let snapshot = client.symbol_get_by_name(name).unwrap();
        assert_eq!(snapshot["symbols"].as_array().unwrap().len(), 1);
        assert_eq!(snapshot["symbols"][0]["name"], name);
        assert_eq!(snapshot["symbols"][0]["address"], address);
        if !name.starts_with("0x") && !name.starts_with("0X") {
            assert_eq!(client.symbol_get(name).unwrap(), snapshot);
        }

        ghidra(harness)
            .args(["symbol", "rename", name, renamed, "--address", &address])
            .run()
            .assert_success();
        let renamed_snapshot = client.symbol_get_by_name(renamed).unwrap();
        assert_eq!(
            renamed_snapshot["symbols"][0]["id"],
            snapshot["symbols"][0]["id"]
        );
        assert!(client.symbol_get_by_name(name).is_err());

        ghidra(harness)
            .args(["symbol", "delete", renamed, "--address", &address])
            .run()
            .assert_success();
        assert!(client.symbol_get_by_name(renamed).is_err());
    }
}

#[test]
#[serial]
fn test_symbol_name_and_address_collisions_preserve_mutation_targets() {
    require_ghidra!();
    let harness = harness();
    let client = harness.client().unwrap();
    let addresses = get_function_addresses(harness, test_project(), TEST_PROGRAM, 2);
    let hex_name = addresses[1].trim_start_matches("0x");
    let explicit_address = format!("0x{hex_name}");
    let uppercase_address = format!("0X{hex_name}");
    let address_symbols = client.symbol_get(&explicit_address).unwrap();

    // The name points to a different address than its hexadecimal spelling.
    client.symbol_create(&addresses[0], hex_name).unwrap();
    client
        .symbol_create(&addresses[0], &explicit_address)
        .unwrap();
    let named = client.symbol_get_by_name(hex_name).unwrap();
    assert_eq!(named["symbols"][0]["address"], addresses[0]);
    assert_eq!(client.symbol_get(hex_name).unwrap(), named);
    assert_eq!(
        client.symbol_get(&explicit_address).unwrap(),
        address_symbols
    );
    assert_eq!(
        client.symbol_get(&uppercase_address).unwrap(),
        address_symbols
    );

    ghidra(harness)
        .args([
            "symbol",
            "rename",
            hex_name,
            "wrong_target",
            "--address",
            &addresses[1],
        ])
        .run()
        .assert_failure()
        .assert_stderr_contains("No symbol named");
    assert_eq!(client.symbol_get_by_name(hex_name).unwrap(), named);

    ghidra(harness)
        .args(["symbol", "delete", hex_name, "--address", &addresses[0]])
        .run()
        .assert_success();
    // Bare hexadecimal text remains an exact name after its label is gone.
    assert!(client.symbol_get(hex_name).is_err());
    assert_eq!(
        client.symbol_get(&explicit_address).unwrap(),
        address_symbols
    );
    for args in [
        vec!["symbol", "delete", hex_name, "--all"],
        vec![
            "symbol",
            "rename",
            hex_name,
            "wrong_target",
            "--address",
            &addresses[1],
        ],
    ] {
        ghidra(harness)
            .args(args)
            .run()
            .assert_failure()
            .assert_stderr_contains("Symbol not found");
    }
    assert_eq!(
        client.symbol_get(&explicit_address).unwrap(),
        address_symbols
    );
    ghidra(harness)
        .args([
            "symbol",
            "delete",
            &explicit_address,
            "--address",
            &addresses[0],
        ])
        .run()
        .assert_success();
}

#[test]
#[serial]
fn test_function_create_recreates_deleted_function_body() {
    require_ghidra!();
    let harness = harness();

    // Regression: `function create` called FunctionManager.createFunction()
    // with a null body, which does not follow flow from the entry point to
    // compute one -- for real, already-disassembled entry points (ARM/Thumb
    // vtable targets in the field report; reproduced here by deleting an
    // ordinary function and recreating it at the same entry) it deterministically
    // rejected the address with "Function body must contain the entrypoint".
    // The fix routes through CreateFunctionCmd, which follows flow like
    // GhidraScript.createFunction()/the UI's "Create Function" action do.
    let addr = get_function_address(harness, test_project(), TEST_PROGRAM, "add_numbers");

    let before = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("function")
        .arg("get")
        .arg(&addr)
        .arg("--project")
        .arg(test_project())
        .arg("--program")
        .arg(TEST_PROGRAM)
        .arg("--format")
        .arg("json")
        .output()
        .expect("Failed to run command");
    assert!(before.status.success());
    let before_json: serde_json::Value =
        serde_json::from_slice(&before.stdout).expect("valid JSON");
    let original_size = before_json[0]["size"].as_u64().expect("size field");

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("function")
        .arg("delete")
        .arg(&addr)
        .arg("--project")
        .arg(test_project())
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("function")
        .arg("create")
        .arg(&addr)
        .arg("add_numbers")
        .arg("--project")
        .arg(test_project())
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    let after = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("function")
        .arg("get")
        .arg(&addr)
        .arg("--project")
        .arg(test_project())
        .arg("--program")
        .arg(TEST_PROGRAM)
        .arg("--format")
        .arg("json")
        .output()
        .expect("Failed to run command");
    assert!(after.status.success());
    let after_json: serde_json::Value = serde_json::from_slice(&after.stdout).expect("valid JSON");
    assert_eq!(
        after_json[0]["size"].as_u64(),
        Some(original_size),
        "recreated function body should match the original (flow-followed, not a stub): {}",
        after_json
    );
}

#[test]
#[serial]
fn test_symbol_targets_revalidate_every_member_and_namespace() {
    require_ghidra!();
    let harness = harness();
    let client = harness.client().unwrap();
    let addresses = get_function_addresses(harness, test_project(), TEST_PROGRAM, 2);
    let name = format!("guarded_symbol_{}", std::process::id());
    client.script_run_source(r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;
public class ScopedSymbolFixture extends GhidraScript {
    public void run() throws Exception {
        String[] a = getScriptArgs();
        SymbolTable st = currentProgram.getSymbolTable();
        for (int i = 0; i < 2; i++) {
            Namespace ns = st.createNameSpace(currentProgram.getGlobalNamespace(), a[1] + i, SourceType.USER_DEFINED);
            st.createLabel(toAddr(a[0]), a[1], ns, SourceType.USER_DEFINED);
        }
    }
}
"#, &[addresses[0].clone(), name.clone()], &[], false).unwrap();
    let snapshot = client.symbol_get(&name).unwrap()["symbols"]
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(snapshot.len(), 2);
    let renamed = format!("{name}_selected");
    client
        .symbol_rename_targets(&name, &renamed, &snapshot[..1])
        .unwrap();
    assert_eq!(
        client.symbol_get(&name).unwrap()["symbols"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    // The still-valid member appears first: reject the stale second member before deleting either.
    let stale = vec![snapshot[1].clone(), snapshot[0].clone()];
    let error = client.symbol_delete_targets(&name, &stale).unwrap_err();
    assert!(error.to_string().contains("Stale"), "{error:#}");
    assert_eq!(
        client.symbol_get(&name).unwrap()["symbols"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    // Legacy addresses must also validate the entire set before mutation.
    assert!(client.symbol_delete(&name, &addresses).is_err());
    assert_eq!(
        client.symbol_get(&name).unwrap()["symbols"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let remaining = client.symbol_get(&name).unwrap()["symbols"]
        .as_array()
        .unwrap()
        .clone();
    client.symbol_delete_targets(&name, &remaining).unwrap();
    let remaining = client.symbol_get(&renamed).unwrap()["symbols"]
        .as_array()
        .unwrap()
        .clone();
    client.symbol_delete_targets(&renamed, &remaining).unwrap();
}

fn create_symbol_fixture_program() -> String {
    let program = format!("symbol-deletion-{}", uuid::Uuid::new_v4());
    let client = harness().client().unwrap();
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;
public class CreateSymbolDeletionProgram extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
        var program = new ProgramDB(getScriptArgs()[0], language,
            language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("symbol deletion fixture");
            try {
                program.getMemory().createInitializedBlock("fixture",
                    program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000),
                    0x100, (byte) 0, monitor, false);
            } finally { program.endTransaction(tx, true); }
            state.getProject().getProjectData().getRootFolder()
                .createFile(getScriptArgs()[0], program, monitor);
        } finally { program.release(this); }
    }
}
"#,
            std::slice::from_ref(&program),
            &[],
            false,
        )
        .unwrap();
    client.open_program(&program).unwrap();
    program
}

#[test]
#[serial]
fn test_default_thunk_names_round_trip_and_keep_mutations_scoped() {
    require_ghidra!();
    let program = create_symbol_fixture_program();
    let harness = harness();
    let client = harness.client().unwrap();
    let checked = std::panic::catch_unwind(|| {
        client
            .script_run_source(
                r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;
public class CreateDefaultThunkNames extends GhidraScript {
    public void run() throws Exception {
        var manager = currentProgram.getFunctionManager();
        var targetAddress = toAddr(0x1020);
        var target = manager.createFunction("default_target", targetAddress,
            new AddressSet(targetAddress, targetAddress), SourceType.USER_DEFINED);
        for (long offset : new long[] {0x1030, 0x1040}) {
            var address = toAddr(offset);
            var thunk = manager.createFunction(null, address,
                new AddressSet(address, address), SourceType.DEFAULT);
            thunk.setThunkedFunction(target);
        }
    }
}
"#,
                &[],
                &[],
                false,
            )
            .unwrap();

        let listed = client.symbol_list(None, None, None).unwrap();
        let before = client.symbol_get("default_target").unwrap();
        assert_eq!(client.symbol_get_by_name("default_target").unwrap(), before);
        assert_eq!(before["symbols"], listed["symbols"]);
        assert_eq!(before["symbols"].as_array().unwrap().len(), 3, "{before}");
        let selected = client.symbol_get("0x1030").unwrap()["symbols"][0].clone();
        let other = client.symbol_get("0x1040").unwrap()["symbols"][0].clone();
        assert_eq!(selected["source"], "DEFAULT");
        assert_eq!(other["source"], "DEFAULT");

        for args in [
            vec!["symbol", "rename", "default_target", "renamed_thunk"],
            vec!["symbol", "delete", "default_target"],
        ] {
            ghidra(harness)
                .args(args)
                .with_project(test_project(), &program)
                .run()
                .assert_failure()
                .assert_stderr_contains("matches 3 symbols");
            assert_eq!(client.symbol_get("default_target").unwrap(), before);
        }

        ghidra(harness)
            .args([
                "symbol",
                "rename",
                "default_target",
                "renamed_thunk",
                "--address",
                "0x1030",
            ])
            .with_project(test_project(), &program)
            .run()
            .assert_success();
        assert_eq!(
            client.symbol_get("renamed_thunk").unwrap()["symbols"][0]["id"],
            selected["id"]
        );
        // Reject every target before mutation, even when the valid member comes first.
        let error = client
            .symbol_delete_targets("default_target", &[other.clone(), selected])
            .unwrap_err();
        assert!(error.to_string().contains("Stale"), "{error:#}");
        assert_eq!(client.symbol_get("0x1040").unwrap()["symbols"][0], other);

        // Legacy address-scoped requests must also find default thunks by displayed name.
        client
            .symbol_rename(
                "default_target",
                "legacy_renamed_thunk",
                &["0x1040".to_string()],
            )
            .unwrap();
        assert_eq!(
            client.symbol_get("legacy_renamed_thunk").unwrap()["symbols"][0]["id"],
            other["id"]
        );
        let remaining = client.symbol_get("default_target").unwrap();
        assert_eq!(remaining["symbols"].as_array().unwrap().len(), 1);
        assert_eq!(remaining["symbols"][0]["source"], "USER_DEFINED");
    });
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&program).unwrap();
    if let Err(panic) = checked {
        std::panic::resume_unwind(panic);
    }
}

#[test]
#[serial]
fn test_symbol_delete_rejects_dynamic_targets_before_deleting_any_member() {
    require_ghidra!();
    let program = create_symbol_fixture_program();
    let harness = harness();
    let client = harness.client().unwrap();
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;
public class CreateDynamicSymbol extends GhidraScript {
    public void run() throws Exception {
        currentProgram.getReferenceManager().addMemoryReference(
            toAddr("1000"), toAddr("1010"), RefType.DATA, SourceType.USER_DEFINED, 0);
        if (!currentProgram.getSymbolTable().getPrimarySymbol(toAddr("1010")).isDynamic())
            throw new IllegalStateException("fixture must have a dynamic label");
    }
}
"#,
            &[],
            &[],
            false,
        )
        .unwrap();
    let dynamic = client.symbol_get("0x1010").unwrap()["symbols"][0].clone();
    let name = dynamic["name"].as_str().unwrap();
    let rejected = ghidra(harness)
        .args(["symbol", "delete", name])
        .with_project(test_project(), &program)
        .arg("--json")
        .run();
    rejected.assert_failure();
    let error: serde_json::Value = serde_json::from_str(&rejected.stderr).unwrap();
    assert!(error["message"]
        .as_str()
        .unwrap()
        .contains("Dynamic symbols"));
    assert_eq!(error["detail"]["count"], 0);
    assert_eq!(error["detail"]["failed"][0]["id"], dynamic["id"]);
    assert!(error["detail"].get("partial_changes_saved").is_none());

    client.symbol_create("0x1020", name).unwrap();
    let stored = client.symbol_get("0x1020").unwrap()["symbols"][0].clone();
    let matches = client.symbol_get_by_name(name).unwrap();
    assert_eq!(matches["symbols"].as_array().unwrap().len(), 2);
    // The valid stored label appears first, so the dynamic member must be
    // rejected before either member is mutated.
    let error = client
        .symbol_delete_targets(name, &[stored.clone(), dynamic.clone()])
        .unwrap_err();
    let error = error
        .downcast_ref::<ghidra_cli::ipc::protocol::BridgeCommandError>()
        .unwrap();
    assert_eq!(error.detail["count"], 0);
    assert_eq!(error.detail["deleted"], serde_json::json!([]));
    assert_eq!(error.detail["failed"][0]["id"], dynamic["id"]);
    assert_eq!(error.detail["not_attempted"], serde_json::json!([stored]));
    assert!(error.detail.get("partial_changes_saved").is_none());
    client.program_close().unwrap();
    client.open_program(&program).unwrap();
    assert_eq!(client.symbol_get("0x1010").unwrap()["symbols"][0], dynamic);
    assert_eq!(client.symbol_get("0x1020").unwrap()["symbols"][0], stored);
    client.open_program(TEST_PROGRAM).unwrap();
}

#[test]
#[serial]
fn test_symbol_delete_preserves_partial_results_and_save_failures() {
    require_ghidra!();
    let client = harness().client().unwrap();
    for prevent_save in [false, true] {
        let program = create_symbol_fixture_program();
        let name = "cascade_target";
        client
            .script_run_source(
                r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;
public class CreateCascadingSymbolDeletion extends GhidraScript {
    public void run() throws Exception {
        var table = currentProgram.getSymbolTable();
        var parent = table.createNameSpace(currentProgram.getGlobalNamespace(),
            getScriptArgs()[0], SourceType.USER_DEFINED);
        table.createLabel(toAddr("1010"), getScriptArgs()[0], parent, SourceType.USER_DEFINED);
        var other = table.createNameSpace(currentProgram.getGlobalNamespace(),
            "unaffected", SourceType.USER_DEFINED);
        table.createLabel(toAddr("1020"), getScriptArgs()[0], other, SourceType.USER_DEFINED);
    }
}
"#,
                &[name.to_owned()],
                &[],
                false,
            )
            .unwrap();
        let selected = client.symbol_get_by_name(name).unwrap()["symbols"]
            .as_array()
            .unwrap()
            .clone();
        let parent = selected.iter().find(|s| s["type"] == "Namespace").unwrap();
        let child = selected.iter().find(|s| s["namespace"] == name).unwrap();
        let unaffected = selected
            .iter()
            .find(|s| s["namespace"] == "unaffected")
            .unwrap();
        let transaction = prevent_save.then(|| {
            let error = client
                .script_run_source(
                    r#"
import ghidra.app.script.GhidraScript;
public class PreventSymbolDeletionSave extends GhidraScript {
    public void run() throws Exception {
        println(Integer.toString(currentProgram.startTransaction("hold deletion save")));
    }
}
"#,
                    &[],
                    &[],
                    false,
                )
                .unwrap_err();
            error
                .downcast_ref::<ghidra_cli::ipc::protocol::BridgeCommandError>()
                .unwrap()
                .detail["command_response"]["data"]["stdout"]
                .as_str()
                .unwrap()
                .trim()
                .to_owned()
        });
        // Deleting the namespace also removes its child. Deleting that selected
        // child next returns false; the unrelated final target must not run.
        let error = client
            .symbol_delete_targets(name, &[parent.clone(), child.clone(), unaffected.clone()])
            .unwrap_err();
        if let Some(transaction) = transaction {
            client
                .script_run_source(
                    r#"
import ghidra.app.script.GhidraScript;
public class ReleaseSymbolDeletionSave extends GhidraScript {
    public void run() throws Exception {
        currentProgram.endTransaction(Integer.parseInt(getScriptArgs()[0]), true);
    }
}
"#,
                    &[transaction],
                    &[],
                    false,
                )
                .unwrap();
        }
        let error = error
            .downcast_ref::<ghidra_cli::ipc::protocol::BridgeCommandError>()
            .unwrap();
        let detail = if prevent_save {
            assert_eq!(error.detail["save_failed"], true);
            assert_eq!(error.detail["saved"], false);
            assert_eq!(error.detail["command_response"]["status"], "error");
            &error.detail["command_response"]["detail"]
        } else {
            assert_eq!(error.detail["partial_changes_saved"], true);
            &error.detail
        };
        assert_eq!(detail["count"], 1);
        assert_eq!(detail["deleted"], serde_json::json!([parent]));
        assert_eq!(detail["failed"][0]["id"], child["id"]);
        assert_eq!(
            detail["failed"][0]["reason"],
            "Ghidra refused to delete symbol"
        );
        assert_eq!(detail["not_attempted"], serde_json::json!([unaffected]));
        client.program_close().unwrap();
        client.open_program(&program).unwrap();
        assert_eq!(
            client.symbol_get_by_name(name).unwrap()["symbols"],
            serde_json::json!([unaffected])
        );
        let deleted = client
            .symbol_delete_targets(name, std::slice::from_ref(unaffected))
            .unwrap();
        assert_eq!(deleted["count"], 1);
        assert_eq!(deleted["deleted"], serde_json::json!([unaffected]));
        client.open_program(TEST_PROGRAM).unwrap();
    }
}

#[test]
#[serial]
fn test_duplicate_function_names_rejected_before_mutation() {
    require_ghidra!();
    let harness = harness();
    let client = harness.client().unwrap();
    let addresses = [
        get_function_address(harness, test_project(), TEST_PROGRAM, "multiply"),
        get_function_address(harness, test_project(), TEST_PROGRAM, "add_numbers"),
    ];
    let before: Vec<serde_json::Value> = addresses
        .iter()
        .map(|address| {
            client
                .send_command("get_function", Some(serde_json::json!({"address":address})))
                .unwrap()
        })
        .collect();
    let duplicate = format!("duplicate_function_{}", std::process::id());
    client.script_run_source(r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;
public class DuplicateFunctionFixture extends GhidraScript {
    public void run() throws Exception {
        String[] a = getScriptArgs();
        for (int i = 0; i < 2; i++) {
            Function f = getFunctionAt(toAddr(a[i]));
            if (!f.getParentNamespace().isGlobal()) throw new IllegalStateException("fixture must be global");
        }
        for (int i = 0; i < 2; i++) {
            Function f = getFunctionAt(toAddr(a[i]));
            Namespace ns = currentProgram.getSymbolTable().createNameSpace(currentProgram.getGlobalNamespace(), a[2] + i, SourceType.USER_DEFINED);
            f.setParentNamespace(ns);
            f.setName(a[2], SourceType.USER_DEFINED);
        }
    }
}
"#, &[addresses[0].clone(), addresses[1].clone(), duplicate.clone()], &[], false).unwrap();
    let selected_before: Vec<serde_json::Value> = addresses
        .iter()
        .map(|address| {
            client
                .send_command("get_function", Some(serde_json::json!({"address":address})))
                .unwrap()
        })
        .collect();
    for (command, args) in [
        (
            "rename_function",
            serde_json::json!({"old_name":duplicate,"new_name":"should_not_rename"}),
        ),
        ("delete_function", serde_json::json!({"address":duplicate})),
        (
            "function_set_return_type",
            serde_json::json!({"target":duplicate,"return_type":"void"}),
        ),
    ] {
        let error = client.send_command(command, Some(args)).unwrap_err();
        assert!(
            error.to_string().contains("Ambiguous"),
            "{command}: {error:#}"
        );
    }
    for (index, address) in addresses.iter().enumerate() {
        let current = client
            .send_command("get_function", Some(serde_json::json!({"address":address})))
            .unwrap();
        assert_eq!(
            current, selected_before[index],
            "ambiguous mutations must preserve every function"
        );
    }
    // Address-qualified rename remains available even when names collide.
    client.send_command("rename_function", Some(serde_json::json!({"old_name":duplicate,"new_name":before[0]["name"],"address":addresses[0]}))).unwrap();
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;
public class RestoreFunctionFixture extends GhidraScript {
    public void run() throws Exception {
        String[] a = getScriptArgs();
        for (int i = 0; i < 2; i++) {
            getFunctionAt(toAddr(a[i])).setParentNamespace(currentProgram.getGlobalNamespace());
            getFunctionAt(toAddr(a[i])).setName(a[i+2], SourceType.USER_DEFINED);
        }
    }
}
"#,
            &[
                addresses[0].clone(),
                addresses[1].clone(),
                before[0]["name"].as_str().unwrap().to_string(),
                before[1]["name"].as_str().unwrap().to_string(),
            ],
            &[],
            false,
        )
        .unwrap();
}
