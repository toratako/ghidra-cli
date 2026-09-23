use super::{ghidra, harness, test_project, TEST_PROGRAM};
use serial_test::serial;

pub(super) fn create_symbol_fixture_program() -> String {
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
    assert!(error["detail"].get("count").is_none());
    assert!(error["detail"].get("deleted").is_none());
    assert_eq!(error["detail"]["attempted_deleted"], serde_json::json!([]));
    assert_eq!(error["detail"]["rolled_back"], true);
    assert_eq!(error["detail"]["failed"][0]["id"], dynamic["id"]);
    assert!(error["detail"].get("partial_changes_saved").is_none());

    client.symbol_create_label("0x1020", name).unwrap();
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
    assert!(error.detail.get("count").is_none());
    assert!(error.detail.get("deleted").is_none());
    assert_eq!(error.detail["attempted_deleted"], serde_json::json!([]));
    assert_eq!(error.detail["rolled_back"], true);
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
fn test_symbol_mutations_reject_namespace_owners_before_mutating_any_member() {
    require_ghidra!();
    let client = harness().client().unwrap();
    for kind in ["namespace", "class"] {
        let program = create_symbol_fixture_program();
        let name = "owned_target";
        client
            .script_run_source(
                r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.*;
public class CreateNamespaceOwnerFixture extends GhidraScript {
    public void run() throws Exception {
        var table = currentProgram.getSymbolTable();
        var global = currentProgram.getGlobalNamespace();
        var owner = getScriptArgs()[0].equals("class")
            ? table.createClass(global, getScriptArgs()[1], SourceType.USER_DEFINED)
            : table.createNameSpace(global, getScriptArgs()[1], SourceType.USER_DEFINED);
        table.createLabel(toAddr("1010"), getScriptArgs()[1], owner, SourceType.USER_DEFINED);
        table.createLabel(toAddr("1020"), getScriptArgs()[1], global, SourceType.USER_DEFINED);
        currentProgram.getFunctionManager().createFunction("owned_function", owner,
            toAddr("1030"), new AddressSet(toAddr("1030"), toAddr("103f")),
            SourceType.USER_DEFINED);
    }
}
"#,
                &[kind.to_owned(), name.to_owned()],
                &[],
                false,
            )
            .unwrap();
        let before = client.symbol_get_by_name(name).unwrap();
        let symbols = before["symbols"].as_array().unwrap();
        let owner = symbols
            .iter()
            .find(|symbol| matches!(symbol["type"].as_str(), Some("Namespace" | "Class")))
            .unwrap();
        let ordinary = client.symbol_get("0x1020").unwrap()["symbols"][0].clone();
        let function_before = client
            .send_command(
                "get_function",
                Some(serde_json::json!({"address": "0x1030"})),
            )
            .unwrap();
        for targets in [vec![owner.clone()], vec![ordinary.clone(), owner.clone()]] {
            for command in ["symbol_delete", "symbol_rename"] {
                // The ordinary symbol comes first: validation must inspect every
                // selected member before a rename or deletion is attempted.
                let error = client
                    .send_command(
                        command,
                        Some(serde_json::json!({
                            "name": name,
                            "old_name": name,
                            "new_name": "must_not_rename",
                            "targets": targets,
                        })),
                    )
                    .unwrap_err();
                assert!(
                    error.to_string().contains("namespace"),
                    "{kind} {command}: {error:#}"
                );
                assert_eq!(client.symbol_get_by_name(name).unwrap(), before);
                assert!(client.symbol_get_by_name("must_not_rename").is_err());
                assert_eq!(
                    client
                        .send_command(
                            "get_function",
                            Some(serde_json::json!({"address": "0x1030"}))
                        )
                        .unwrap(),
                    function_before
                );
            }
        }
        client.program_close().unwrap();
        client.open_program(&program).unwrap();
        assert_eq!(client.symbol_get_by_name(name).unwrap(), before);
        assert_eq!(
            client
                .send_command(
                    "get_function",
                    Some(serde_json::json!({"address": "0x1030"}))
                )
                .unwrap(),
            function_before
        );
        client.open_program(TEST_PROGRAM).unwrap();
        client.program_delete(&program).unwrap();
    }
}

#[test]
#[serial]
fn test_symbol_delete_rolls_back_function_child_deletion_and_rejects_foreign_transactions() {
    require_ghidra!();
    let client = harness().client().unwrap();
    for prevent_save in [false, true] {
        let program = create_symbol_fixture_program();
        let name = "cascade_target";
        client
            .script_run_source(
                r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.*;
public class CreateCascadingSymbolDeletion extends GhidraScript {
    public void run() throws Exception {
        var table = currentProgram.getSymbolTable();
        var parent = currentProgram.getFunctionManager().createFunction(getScriptArgs()[0],
            toAddr("1000"), new AddressSet(toAddr("1000"), toAddr("101f")),
            SourceType.USER_DEFINED);
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
        let parent = selected.iter().find(|s| s["type"] == "Function").unwrap();
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
        // Deleting a function also removes its local label. Deleting that selected
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
        if prevent_save {
            // This request cannot own an atomic transaction while a script's
            // transaction remains open. Reject it without attempting deletion.
            assert_eq!(error.detail["transaction_failed"], true);
            assert!(error.detail.get("rolled_back").is_none());
            assert!(error.detail.get("save_failed").is_none());
            assert!(error.detail.get("attempted_deleted").is_none());
        } else {
            assert_eq!(error.detail["rolled_back"], true);
            assert!(error.detail.get("count").is_none());
            assert!(error.detail.get("deleted").is_none());
            assert_eq!(
                error.detail["attempted_deleted"],
                serde_json::json!([parent])
            );
            assert_eq!(error.detail["failed"][0]["id"], child["id"]);
            assert_eq!(
                error.detail["failed"][0]["reason"],
                "Ghidra refused to delete symbol"
            );
            assert_eq!(
                error.detail["not_attempted"],
                serde_json::json!([unaffected])
            );
        }
        assert!(error.detail.get("partial_changes_saved").is_none());
        assert_eq!(
            client.symbol_get_by_name(name).unwrap()["symbols"],
            serde_json::json!(selected)
        );
        client.program_close().unwrap();
        client.open_program(&program).unwrap();
        assert_eq!(
            client.symbol_get_by_name(name).unwrap()["symbols"],
            serde_json::json!(selected)
        );
        let deleted = client
            .symbol_delete_targets(name, std::slice::from_ref(unaffected))
            .unwrap();
        assert_eq!(deleted["count"], 1);
        assert_eq!(deleted["deleted"], serde_json::json!([unaffected]));
        client.open_program(TEST_PROGRAM).unwrap();
    }
}
