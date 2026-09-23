use super::{command, ghidra, harness, move_symbol, symbol, test_project, with_fixture};
use ghidra_cli::ipc::client::BridgeClient;
use serde_json::{json, Value};
use serial_test::serial;
use std::collections::{BTreeMap, BTreeSet};

fn namespace(client: &BridgeClient, path: &str) -> Value {
    client
        .send_command("namespace_get", Some(json!({"path":path})))
        .unwrap()
}

fn state(client: &BridgeClient) -> Value {
    let result = client
        .script_run_source(include_str!("ReadNamespaceEditState.java"), &[], &[], false)
        .unwrap();
    serde_json::from_str(result["stdout"].as_str().unwrap().trim()).unwrap()
}

fn ids(rows: &Value) -> BTreeSet<String> {
    rows.as_array()
        .unwrap()
        .iter()
        .map(|row| row["id"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
#[serial]
fn namespace_rename_and_move_preserve_subtree_identity_and_reopen() {
    require_ghidra!();
    with_fixture(|client, program| {
        command(program, &["namespace", "create", "app"]);
        command(
            program,
            &["namespace", "create", "child", "--parent", "app"],
        );
        let app = namespace(client, "app");
        let child = namespace(client, "app::child");
        let label = move_symbol(client, &symbol(client, "first_label"), Some("app::child"));
        let function = move_symbol(client, &symbol(client, "plain"), Some("app::child"));
        let before = state(client);
        let renamed = command(program, &["namespace", "rename", "app", "core"]);
        assert_eq!(renamed["status"], "renamed");
        assert_eq!(renamed["before"], app);
        assert_eq!(renamed["after"]["id"], app["id"]);
        assert_eq!(renamed["after"]["path"], "core");
        assert_eq!(namespace(client, "core::child")["id"], child["id"]);
        assert_eq!(symbol(client, "first_label")["id"], label["after"]["id"]);
        assert_eq!(symbol(client, "first_label")["namespace"], "core::child");
        assert_eq!(symbol(client, "plain")["id"], function["after"]["id"]);
        assert_eq!(symbol(client, "plain")["namespace"], "core::child");
        assert_eq!(
            command(program, &["namespace", "rename", "core", "core"])["status"],
            "unchanged"
        );

        let moved = command(program, &["namespace", "move", "core", "--parent", "right"]);
        assert_eq!(moved["status"], "moved");
        assert_eq!(moved["before"], renamed["after"]);
        assert_eq!(moved["after"]["id"], app["id"]);
        assert_eq!(moved["after"]["parent"], "right");
        assert_eq!(namespace(client, "right::core::child")["id"], child["id"]);
        assert_eq!(symbol(client, "plain")["namespace"], "right::core::child");
        assert_eq!(
            command(
                program,
                &["namespace", "move", "right::core", "--parent", "right"]
            )["status"],
            "unchanged"
        );
        let global = command(program, &["namespace", "move", "right::core", "--global"]);
        assert_eq!(global["after"], renamed["after"]);
        let after = state(client);
        assert_eq!(ids(&after["symbols"]), ids(&before["symbols"]));
        assert_eq!(after["bytes"], before["bytes"]);
        client.program_close().unwrap();
        client.open_program(program).unwrap();
        assert_eq!(state(client), after);
        assert_eq!(namespace(client, "core::child")["id"], child["id"]);
    });
}

#[test]
#[serial]
fn namespace_delete_requires_empty_or_explicit_recursion_and_reports_all_removed_symbols() {
    require_ghidra!();
    with_fixture(|client, program| {
        command(program, &["namespace", "create", "app"]);
        command(
            program,
            &[
                "namespace",
                "create",
                "Widget",
                "--parent",
                "app",
                "--kind",
                "class",
            ],
        );
        command(
            program,
            &["namespace", "create", "empty", "--parent", "app"],
        );
        move_symbol(client, &symbol(client, "method"), Some("app::Widget"));
        move_symbol(client, &symbol(client, "first_label"), Some("app::Widget"));
        client
            .script_run_source(
                r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.symbol.SourceType;
public class AddNamespaceLocal extends GhidraScript {
    public void run() throws Exception {
        getFunctionAt(toAddr(0x1040)).addLocalVariable(new LocalVariableImpl("scratch",
            IntegerDataType.dataType, -4, currentProgram), SourceType.USER_DEFINED);
    }
}
"#,
                &[],
                &[],
                false,
            )
            .unwrap();
        let before = state(client);
        for path in ["app", "app::Widget"] {
            ghidra(harness())
                .args(["namespace", "delete", path])
                .with_project(test_project(), program)
                .run()
                .assert_failure();
            assert_eq!(state(client), before);
        }
        let empty = namespace(client, "app::empty");
        let deleted_empty = command(program, &["namespace", "delete", "app::empty"]);
        assert_eq!(deleted_empty["target"], empty);
        assert_eq!(deleted_empty["recursive"], false);
        assert_eq!(deleted_empty["count"], 1);
        assert_eq!(deleted_empty["deleted"][0]["id"], empty["id"]);
        let before = state(client);
        let target = namespace(client, "app");
        let receipt = command(program, &["namespace", "delete", "app", "--recursive"]);
        assert_eq!(receipt["target"], target);
        assert_eq!(receipt["recursive"], true);
        assert_eq!(receipt["status"], "deleted");
        let expected: Vec<_> = before["symbols"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| {
                row["path"] == "app" || row["path"].as_str().unwrap().starts_with("app::")
            })
            .cloned()
            .collect();
        assert!(expected.iter().any(|row| row["name"] == "scratch"));
        assert!(expected.iter().any(|row| row["name"] == "value"));
        assert_eq!(ids(&receipt["deleted"]), ids(&json!(expected)));
        assert_eq!(receipt["count"].as_u64().unwrap() as usize, expected.len());
        let mut counts = BTreeMap::<String, usize>::new();
        for row in &expected {
            *counts
                .entry(row["type"].as_str().unwrap().to_owned())
                .or_default() += 1;
            let actual = receipt["deleted"]
                .as_array()
                .unwrap()
                .iter()
                .find(|item| item["id"] == row["id"])
                .unwrap();
            for field in ["id", "name", "path", "type"] {
                assert_eq!(actual[field], row[field]);
            }
        }
        assert_eq!(receipt["counts"], json!(counts));
        let after = state(client);
        let removed: BTreeSet<_> = ids(&before["symbols"])
            .difference(&ids(&after["symbols"]))
            .cloned()
            .collect();
        assert_eq!(removed, ids(&receipt["deleted"]));
        assert_eq!(after["bytes"], before["bytes"]);
        assert_eq!(after["functions"].as_array().unwrap().len(), 1);
        assert_eq!(after["functions"][0]["path"], "plain");
        let unaffected: Vec<_> = before["symbols"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| !removed.contains(row["id"].as_str().unwrap()))
            .cloned()
            .collect();
        assert_eq!(after["symbols"], json!(unaffected));
        // Native class deletion leaves its associated datatype available.
        assert!(client.type_get("/app/Widget").is_ok());
        client.program_close().unwrap();
        client.open_program(program).unwrap();
        assert_eq!(state(client), after);
        assert!(client.type_get("/app/Widget").is_ok());
    });
}

#[test]
#[serial]
fn namespace_mutations_revalidate_target_and_parent_and_reject_subtree_collisions() {
    require_ghidra!();
    with_fixture(|client, program| {
        command(program, &["namespace", "create", "app"]);
        command(
            program,
            &["namespace", "create", "child", "--parent", "app"],
        );
        command(program, &["namespace", "create", "core::child"]);
        command(program, &["namespace", "create", "right::app::child"]);
        let app = namespace(client, "app");
        let right = namespace(client, "right");
        let before = state(client);
        for args in [
            vec!["namespace", "rename", "app", "core"],
            vec!["namespace", "rename", "app", "left"],
            vec!["namespace", "move", "app", "--parent", "right"],
            vec!["namespace", "move", "app", "--parent", "app::child"],
            vec!["namespace", "move", "app", "--parent", "app"],
        ] {
            ghidra(harness())
                .args(args)
                .with_project(test_project(), program)
                .run()
                .assert_failure();
            assert_eq!(state(client), before);
        }
        command(program, &["namespace", "rename", "app", "renamed"]);
        let renamed = namespace(client, "renamed");
        command(program, &["namespace", "rename", "right", "destination"]);
        let before = state(client);
        for (operation, args) in [
            ("namespace_rename", json!({"target":app,"new_name":"wrong"})),
            ("namespace_move", json!({"target":app,"parent":null})),
            ("namespace_delete", json!({"target":app,"recursive":true})),
            ("namespace_move", json!({"target":renamed,"parent":right})),
            (
                "namespace_delete",
                json!({"target":{"id":renamed["id"]},"recursive":true}),
            ),
        ] {
            client.send_command(operation, Some(args)).unwrap_err();
            assert_eq!(state(client), before);
        }
        client.program_close().unwrap();
        client.open_program(program).unwrap();
        assert_eq!(state(client), before);
    });
}

#[test]
#[serial]
fn namespace_id_selection_recovers_native_path_ambiguity_without_editing_its_twin() {
    require_ghidra!();
    with_fixture(|client, program| {
        client
            .script_run_source(include_str!("CreateNamespacePaths.java"), &[], &[], false)
            .unwrap();
        let all = client.send_command("namespace_list", None).unwrap();
        let flat = all["namespaces"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["path"] == "a::b" && row["parent"].is_null())
            .unwrap();
        let nested = all["namespaces"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["path"] == "a::b" && row["parent"] == "a")
            .unwrap();
        let before = state(client);
        for args in [
            vec!["namespace", "rename", "a::b", "flat"],
            vec!["namespace", "move", "a::b", "--parent", "right"],
            vec!["namespace", "delete", "a::b", "--recursive"],
            vec!["namespace", "rename", "a::b", "flat", "--where", "id='0'"],
        ] {
            ghidra(harness())
                .args(args)
                .with_project(test_project(), program)
                .run()
                .assert_failure();
            assert_eq!(state(client), before);
        }
        let selector = format!("id='{}'", flat["id"].as_str().unwrap());
        let renamed = command(
            program,
            &["namespace", "rename", "a::b", "flat", "--where", &selector],
        );
        assert_eq!(renamed["before"], *flat);
        assert_eq!(renamed["after"]["id"], flat["id"]);
        assert_eq!(namespace(client, "a::b"), *nested);
        assert_eq!(symbol(client, "flat_marker")["namespace"], "flat");
        assert_eq!(symbol(client, "nested_marker")["namespace"], "a::b");
        // A pre-existing ambiguous pair can move together without creating a new collision.
        client.script_run_source(r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.SourceType;
public class CreateAmbiguousNamespaceSubtree extends GhidraScript {
    public void run() throws Exception {
        var table = currentProgram.getSymbolTable();
        var root = table.createNameSpace(currentProgram.getGlobalNamespace(), "tree", SourceType.USER_DEFINED);
        table.createNameSpace(root, "x::y", SourceType.USER_DEFINED);
        var x = table.createNameSpace(root, "x", SourceType.USER_DEFINED);
        table.createNameSpace(x, "y", SourceType.USER_DEFINED);
    }
}
"#, &[], &[], false).unwrap();
        let before_ids = ids(&client.send_command("namespace_list", None).unwrap()["namespaces"]);
        command(program, &["namespace", "rename", "tree", "renamed_tree"]);
        command(
            program,
            &["namespace", "move", "renamed_tree", "--parent", "right"],
        );
        let after = client.send_command("namespace_list", None).unwrap();
        assert_eq!(ids(&after["namespaces"]), before_ids);
        assert_eq!(
            after["namespaces"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|row| row["path"] == "right::renamed_tree::x::y")
                .count(),
            2
        );
        client.program_close().unwrap();
        client.open_program(program).unwrap();
        assert_eq!(namespace(client, "flat")["id"], flat["id"]);
        assert_eq!(namespace(client, "a::b"), *nested);
    });
}

#[test]
#[serial]
fn recursive_namespace_deletion_rejects_thunk_cascades_outside_the_selected_tree() {
    require_ghidra!();
    with_fixture(|client, program| {
        command(program, &["namespace", "create", "app"]);
        move_symbol(client, &symbol(client, "plain"), Some("app"));
        client
            .script_run_source(
                r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;
public class CreateNamespaceThunks extends GhidraScript {
    public void run() throws Exception {
        var manager = currentProgram.getFunctionManager();
        var target = getFunctionAt(toAddr(0x1050));
        var inside = manager.createFunction("inside_thunk", toAddr(0x1060),
            new AddressSet(toAddr(0x1060)), SourceType.USER_DEFINED);
        inside.setParentNamespace(target.getParentNamespace());
        inside.setThunkedFunction(target);
        var outside = manager.createFunction("outside_thunk", toAddr(0x1070),
            new AddressSet(toAddr(0x1070)), SourceType.USER_DEFINED);
        outside.setThunkedFunction(inside);
        var indirect = manager.createFunction("indirect_thunk", toAddr(0x1080),
            new AddressSet(toAddr(0x1080)), SourceType.USER_DEFINED);
        indirect.setThunkedFunction(outside);
    }
}
"#,
                &[],
                &[],
                false,
            )
            .unwrap();
        let before = state(client);
        ghidra(harness())
            .args(["namespace", "delete", "app", "--recursive"])
            .with_project(test_project(), program)
            .run()
            .assert_failure();
        assert_eq!(state(client), before);
        move_symbol(client, &symbol(client, "outside_thunk"), Some("app"));
        let before = state(client);
        ghidra(harness())
            .args(["namespace", "delete", "app", "--recursive"])
            .with_project(test_project(), program)
            .run()
            .assert_failure();
        assert_eq!(state(client), before);
        move_symbol(client, &symbol(client, "indirect_thunk"), Some("app"));
        let before = state(client);
        let receipt = command(program, &["namespace", "delete", "app", "--recursive"]);
        let after = state(client);
        let removed: BTreeSet<_> = ids(&before["symbols"])
            .difference(&ids(&after["symbols"]))
            .cloned()
            .collect();
        assert_eq!(ids(&receipt["deleted"]), removed);
        assert_eq!(receipt["counts"]["Function"], 4);
        assert_eq!(after["functions"].as_array().unwrap().len(), 1);
        assert_eq!(after["functions"][0]["path"], "method");
        assert_eq!(after["bytes"], before["bytes"]);
        client.program_close().unwrap();
        client.open_program(program).unwrap();
        assert_eq!(state(client), after);
    });
}

#[test]
#[serial]
fn class_namespace_edits_preserve_native_method_abi_and_existing_datatypes() {
    require_ghidra!();
    with_fixture(|client, program| {
        command(program, &["namespace", "create", "app"]);
        command(
            program,
            &[
                "namespace",
                "create",
                "Widget",
                "--parent",
                "app",
                "--kind",
                "class",
            ],
        );
        let class = namespace(client, "app::Widget");
        let moved = move_symbol(client, &symbol(client, "method"), Some("app::Widget"));
        client
            .script_run_source(
                r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;
public class CreateClassDefaultThunk extends GhidraScript {
    public void run() throws Exception {
        var thunk = currentProgram.getFunctionManager().createFunction(null, toAddr(0x1060),
            new AddressSet(toAddr(0x1060)), SourceType.DEFAULT);
        thunk.setThunkedFunction(getFunctionAt(toAddr(0x1040)));
    }
}
"#,
                &[],
                &[],
                false,
            )
            .unwrap();
        let thunk = client.symbol_get("0x1060").unwrap()["symbols"][0].clone();
        let type_before = client.type_get("/app/Widget").unwrap();
        let function = |client: &BridgeClient, address: &str| {
            let result = client
                .send_command(
                    "get_function",
                    Some(json!({"address":address, "with_signature":true})),
                )
                .unwrap();
            let mut signature = result["signature_details"].clone();
            signature["calling_convention"] = result["calling_convention"].clone();
            signature
        };
        let before = function(client, "0x1040");
        let thunk_before = function(client, "0x1060");
        assert_eq!(before["calling_convention"], "__thiscall");
        let renamed = command(program, &["namespace", "rename", "app::Widget", "Renamed"]);
        assert_eq!(renamed["after"]["id"], class["id"]);
        assert_eq!(renamed["after"]["kind"], "class");
        let after_rename = function(client, "0x1040");
        let thunk_after_rename = function(client, "0x1060");
        let changes = renamed["function_changes"].as_array().unwrap();
        assert_eq!(changes.len(), 2, "{renamed}");
        for (id, old, new) in [
            (&moved["after"]["id"], &before, &after_rename),
            (&thunk["id"], &thunk_before, &thunk_after_rename),
        ] {
            let change = changes.iter().find(|row| row["id"] == *id).unwrap();
            assert_eq!(change["before"]["params"], old["params"]);
            assert_eq!(change["after"]["params"], new["params"]);
        }
        assert_eq!(
            after_rename["calling_convention"],
            before["calling_convention"]
        );
        assert_eq!(after_rename["params"][0]["auto_parameter"], "THIS");
        assert_eq!(
            after_rename["params"][0]["storage"],
            before["params"][0]["storage"]
        );
        assert!(
            after_rename["params"][0]["type"]
                .as_str()
                .unwrap()
                .contains("Renamed"),
            "{after_rename}"
        );
        assert_eq!(after_rename["params"][1], before["params"][1]);
        assert_eq!(client.type_get("/app/Widget").unwrap(), type_before);
        let moved_class = command(
            program,
            &["namespace", "move", "app::Renamed", "--parent", "right"],
        );
        assert_eq!(moved_class["after"]["id"], class["id"]);
        let method = client.symbol_get("0x1040").unwrap()["symbols"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["id"] == moved["after"]["id"])
            .unwrap()
            .clone();
        assert_eq!(method["namespace"], "right::Renamed");
        let after_move = function(client, "0x1040");
        let thunk_after_move = function(client, "0x1060");
        assert_eq!(
            after_move["calling_convention"],
            before["calling_convention"]
        );
        let mut expected_params = after_rename["params"].clone();
        assert_eq!(expected_params[0]["type_path"], "/app/Renamed *");
        expected_params[0]["type_path"] = json!("/right/Renamed *");
        assert_eq!(after_move["params"], expected_params);
        let changes = moved_class["function_changes"].as_array().unwrap();
        assert_eq!(changes.len(), 2, "{moved_class}");
        for (id, old, new) in [
            (&moved["after"]["id"], &after_rename, &after_move),
            (&thunk["id"], &thunk_after_rename, &thunk_after_move),
        ] {
            let change = changes.iter().find(|row| row["id"] == *id).unwrap();
            assert_eq!(change["before"]["params"], old["params"]);
            assert_eq!(change["after"]["params"], new["params"]);
        }
        assert_eq!(client.type_get("/app/Widget").unwrap(), type_before);
        client.program_close().unwrap();
        client.open_program(program).unwrap();
        assert_eq!(function(client, "0x1040"), after_move);
        assert_eq!(function(client, "0x1060"), thunk_after_move);
        assert_eq!(namespace(client, "right::Renamed")["id"], class["id"]);
        assert_eq!(client.type_get("/app/Widget").unwrap(), type_before);
    });
}
