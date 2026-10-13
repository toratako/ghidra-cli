use super::{ghidra, harness, test_project, TEST_PROGRAM};
use serde_json::{json, Value};
use serial_test::serial;

#[test]
#[serial]
fn inferred_parameter_edits_preserve_partially_saved_parameter_metadata() {
    require_ghidra!();
    let client = harness().client().unwrap();
    let program = super::return_types::create_fixture();
    super::common::with_temporary_program(&client, &program, TEST_PROGRAM, || {
        let state = || {
            client
                .send_command(
                    "get_function",
                    Some(json!({"address":"partial", "with_signature":true})),
                )
                .unwrap()
        };
        let before = state();
        let variables = client
            .send_command("function_var_list", Some(json!({"target":"partial"})))
            .unwrap();
        let inferred = variables["variables"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["kind"] == "parameter" && row["ordinal"] == 1)
            .unwrap();
        let edited = client
            .send_command(
                "function_var_set",
                Some(json!({"target":"partial", "var_name":inferred["name"], "new_name":"count"})),
            )
            .unwrap();
        assert!(edited["before"].is_null(), "{edited}");
        assert_eq!(edited["after"]["name"], "count");
        assert_eq!(edited["after"]["type"], "undefined4");
        let after = state();
        assert_eq!(
            after["signature_details"]["params"][0],
            before["signature_details"]["params"][0]
        );
        assert_eq!(
            after["signature_details"]["return"],
            before["signature_details"]["return"]
        );
        client.program_close().unwrap();
        client.open_program(&program).unwrap();
        assert_eq!(state(), after);
        client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.SourceType;
public class CheckVariableParameterMetadata extends GhidraScript {
    public void run() throws Exception {
        var parameter = getFunctionAt(toAddr(0x10a0)).getParameter(0);
        if (!"buffer".equals(parameter.getName()) || parameter.getSource() != SourceType.USER_DEFINED
                || !"retain partially saved parameter".equals(parameter.getComment()))
            throw new IllegalStateException("Variable edit replaced existing parameter metadata");
    }
}
"#,
            &[],
            &[],
            false,
        )
        .unwrap();
    });
}

#[test]
#[serial]
fn variable_edits_preserve_hidden_saved_locals_unless_the_symbol_is_a_locked_merge() {
    require_ghidra!();
    let client = harness().client().unwrap();
    for locked in [false, true] {
        let program = format!("variable-numbered-{}", uuid::Uuid::new_v4());
        client
            .script_run_source(
                include_str!("../fixtures/types/CreateVariableTestProgram.java"),
                std::slice::from_ref(&program),
                &[],
                false,
            )
            .unwrap();
        super::common::with_temporary_program(&client, &program, TEST_PROGRAM, || {
            client
                .script_run_source(
                    r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.Undefined4DataType;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.symbol.SourceType;
public class AddNumberedVariableGroup extends GhidraScript {
    public void run() throws Exception {
        var function = getFunctionAt(toAddr(0x1000));
        var type = Boolean.parseBoolean(getScriptArgs()[0])
            ? IntegerDataType.dataType : Undefined4DataType.dataType;
        function.addLocalVariable(new LocalVariableImpl("value", type,
            -8, currentProgram), SourceType.USER_DEFINED);
        function.addLocalVariable(new LocalVariableImpl("value$1", 0x18, type,
            currentProgram.getRegister("EAX"), currentProgram), SourceType.USER_DEFINED);
    }
}
"#,
                    &[locked.to_string()],
                    &[],
                    false,
                )
                .unwrap();
            let saved_state = |name: &str| {
                client
                    .script_run_source(
                        r#"
import ghidra.app.script.GhidraScript;
public class CheckNumberedVariableState extends GhidraScript {
    public void run() throws Exception {
        var locals = getFunctionAt(toAddr(0x1000)).getLocalVariables();
        var names = java.util.Arrays.stream(locals).map(local -> local.getName())
            .collect(java.util.stream.Collectors.toSet());
        String name = getScriptArgs()[0];
        if (locals.length != 2 || !names.equals(java.util.Set.of(name, name + "$1")))
            throw new IllegalStateException("Unexpected numbered local names: " + names);
        for (var local : locals) {
            if (!getScriptArgs()[1].equals(local.getDataType().getName()))
                throw new IllegalStateException("Numbered local type was changed");
        }
    }
}
"#,
                        &[
                            name.into(),
                            if locked { "int" } else { "undefined4" }.into(),
                        ],
                        &[],
                        false,
                    )
                    .unwrap();
            };
            let list = || {
                client
                    .send_command("function_var_list", Some(json!({"target":"edit_target"})))
                    .unwrap()
            };
            saved_state("value");
            let before = list();
            assert!(
                before["variables"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|row| row["name"] == "value"),
                "{before}"
            );
            let edit = client.send_command(
                "function_var_set",
                Some(json!({"target":"edit_target", "var_name":"value", "new_name":"renamed"})),
            );
            let expected_name = if locked {
                assert_eq!(edit.unwrap()["after"]["name"], "renamed");
                "renamed"
            } else {
                let failed = edit.unwrap_err();
                let error = failed
                    .downcast_ref::<ghidra_cli::ipc::protocol::BridgeCommandError>()
                    .unwrap();
                assert!(error.to_string().contains("value$1"), "{error:?}");
                assert_eq!(error.detail["rolled_back"], true, "{error:?}");
                assert_eq!(list()["variables"], before["variables"]);
                "value"
            };
            let after = list();
            for reopen in [false, true] {
                if reopen {
                    client.program_close().unwrap();
                    client.open_program(&program).unwrap();
                }
                assert_eq!(list()["variables"], after["variables"]);
                saved_state(expected_name);
            }
        });
    }
}

#[test]
#[serial]
fn variable_resize_preserves_neighboring_saved_locals_for_saved_and_inferred_targets() {
    require_ghidra!();
    let client = harness().client().unwrap();
    for already_saved in [false, true] {
        let program = format!("variable-resize-{}", uuid::Uuid::new_v4());
        client
            .script_run_source(
                include_str!("../fixtures/types/CreateVariableTestProgram.java"),
                std::slice::from_ref(&program),
                &[],
                false,
            )
            .unwrap();
        client.open_program(&program).unwrap();
        let listed = client
            .send_command("function_var_list", Some(json!({"target":"edit_target"})))
            .unwrap();
        let local = listed["variables"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["kind"] == "local")
            .unwrap();
        let variable_name = if already_saved {
            client
                .send_command(
                    "function_var_set",
                    Some(json!({"target":"edit_target", "var_name":local["name"], "new_name":"guarded"})),
                )
                .unwrap();
            "guarded"
        } else {
            local["name"].as_str().unwrap()
        };
        client
            .script_run_source(
                r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.symbol.SourceType;
public class AddVariableResizeNeighbor extends GhidraScript {
    public void run() throws Exception {
        var function = getFunctionAt(toAddr(0x1000));
        for (var local : function.getLocalVariables()) {
            if (!"guarded".equals(local.getName()) || local.getStackOffset() != -8)
                throw new IllegalStateException("Unexpected stack-local layout");
        }
        function.addLocalVariable(new LocalVariableImpl("kept_neighbor", IntegerDataType.dataType,
            -4, currentProgram), SourceType.USER_DEFINED);
    }
}
"#,
                &[],
                &[],
                false,
            )
            .unwrap();
        let state = || {
            client
                .send_command(
                    "get_function",
                    Some(
                        json!({"address":"edit_target", "with_signature":true, "with_frame":true}),
                    ),
                )
                .unwrap()
        };
        let before = state();
        let failed = client
            .send_command(
                "function_var_set",
                Some(json!({"target":"edit_target", "var_name":variable_name,
                    "new_name":"resized", "type_name":"longlong"})),
            )
            .unwrap_err();
        let error = failed
            .downcast_ref::<ghidra_cli::ipc::protocol::BridgeCommandError>()
            .unwrap();
        assert!(error.to_string().contains("kept_neighbor"), "{error:?}");
        assert_eq!(error.detail["rolled_back"], true, "{error:?}");
        assert_eq!(state(), before);
        client.program_close().unwrap();
        client.open_program(&program).unwrap();
        assert_eq!(state(), before);
        client
            .script_run_source(
                r#"
import ghidra.app.script.GhidraScript;
public class RemoveVariableResizeNeighbor extends GhidraScript {
    public void run() throws Exception {
        var function = getFunctionAt(toAddr(0x1000));
        for (var local : function.getLocalVariables()) {
            if ("kept_neighbor".equals(local.getName())) function.removeVariable(local);
        }
    }
}
"#,
                &[],
                &[],
                false,
            )
            .unwrap();
        let resized = client
            .send_command(
                "function_var_set",
                Some(json!({"target":"edit_target", "var_name":variable_name,
                    "new_name":"resized", "type_name":"longlong"})),
            )
            .unwrap();
        assert_eq!(resized["after"]["name"], "resized");
        assert_eq!(resized["after"]["size"], 8);
        client.open_program(TEST_PROGRAM).unwrap();
        client.program_delete(&program).unwrap();
    }
}

#[test]
#[serial]
fn variable_selection_rejects_identical_program_in_another_project() {
    require_ghidra!();
    let root = tempfile::Builder::new()
        .prefix("ghidra-variable-project-")
        .tempdir()
        .unwrap();
    let source = root.path().join("source/project");
    let destination = root.path().join("destination/project");
    let program = "matching-variables";
    let binary = root.path().join("starter.bin");
    std::fs::write(&binary, [0xc3]).unwrap();
    let installation = ghidra_cli::config::Config::load()
        .unwrap()
        .get_ghidra_installation()
        .unwrap();
    let starter = ghidra_cli::ghidra::bridge::import_oneshot(
        &source,
        &binary,
        &installation,
        &ghidra_cli::ghidra::bridge::OneShotImportOptions {
            language: Some("x86:LE:32:default".into()),
            loader: Some("BinaryLoader".into()),
            ..Default::default()
        },
    )
    .unwrap()
    .program;
    {
        let harness =
            super::common::DaemonTestHarness::new(source.to_str().unwrap(), &starter).unwrap();
        let client = harness.client().unwrap();
        client
            .script_run_source(
                include_str!("../fixtures/types/CreateVariableTestProgram.java"),
                &[program.to_owned()],
                &[],
                false,
            )
            .unwrap();
    }
    super::common::fixture::copy_project(&source, &destination).unwrap();
    let source_harness =
        super::common::DaemonTestHarness::new(source.to_str().unwrap(), program).unwrap();
    let destination_harness =
        super::common::DaemonTestHarness::new(destination.to_str().unwrap(), program).unwrap();
    let source_client = source_harness.client().unwrap();
    let destination_client = destination_harness.client().unwrap();
    let list = |client: &ghidra_cli::ipc::client::BridgeClient| {
        client
            .send_command("function_var_list", Some(json!({"target":"edit_target"})))
            .unwrap()
    };
    let source_snapshot = list(&source_client);
    let destination_snapshot = list(&destination_client);
    for field in ["program", "address", "modification", "variables"] {
        assert_eq!(
            source_snapshot[field], destination_snapshot[field],
            "{field}"
        );
    }
    assert_ne!(source_snapshot["project"], destination_snapshot["project"]);
    let row = source_snapshot["variables"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"] == "input")
        .unwrap();
    let selection = json!({
        "project": source_snapshot["project"],
        "program": source_snapshot["program"],
        "function_address": source_snapshot["address"],
        "modification": source_snapshot["modification"],
        "variable": row,
    });
    let error = destination_client
        .send_command(
            "function_var_set",
            Some(json!({"target":"edit_target", "var_name":"input",
                "selection":selection, "new_name":"wrong_target"})),
        )
        .unwrap_err();
    assert!(error.to_string().contains("stale"), "{error}");
    let after = list(&destination_client);
    assert_eq!(after["variables"], destination_snapshot["variables"]);
    let selected = destination_client
        .send_command(
            "function_var_get",
            Some(
                json!({"target":"edit_target", "var_name":"input", "selection":{
                    "project": after["project"],
                    "program": after["program"],
                    "function_address": after["address"],
                    "modification": after["modification"],
                    "variable": row,
                }}),
            ),
        )
        .unwrap();
    assert_eq!(selected["decompiler"], *row);
}

#[test]
#[serial]
fn function_variables_read_inferred_definitions_and_persist_selected_edits() {
    require_ghidra!();
    let harness = harness();
    let client = harness.client().unwrap();
    let program = format!("variables-{}", uuid::Uuid::new_v4());
    // Address-taking keeps a real stack local visible to the decompiler. The
    // local starts inferred, so rename-only must not pin its inferred int type.
    client
        .script_run_source(
            include_str!("../fixtures/types/CreateVariableTestProgram.java"),
            std::slice::from_ref(&program),
            &[],
            false,
        )
        .unwrap();
    client.open_program(&program).unwrap();

    let decompile = || {
        let output = ghidra(harness)
            .args([
                "decompile",
                "edit_target",
                "--with-vars",
                "--with-params",
                "--json",
            ])
            .with_project(test_project(), &program)
            .run();
        output.assert_success();
        output.data::<serde_json::Value>()
    };
    let edit = |variable: &str, flags: &[&str]| {
        ghidra(harness)
            .args([
                "function",
                "var",
                "set",
                "edit_target",
                "--var",
                variable,
                "--json",
            ])
            .args(flags.iter().copied())
            .with_project(test_project(), &program)
            .run()
    };
    let initial = decompile();
    let locals = initial["variables"].as_array().unwrap();
    assert_eq!(locals.len(), 1, "{initial}");
    let original = &locals[0];

    let list = || {
        client
            .send_command("function_var_list", Some(json!({"target":"edit_target"})))
            .unwrap()
    };
    let listed = list();
    let rows = listed["variables"].as_array().unwrap();
    assert_eq!(rows.len(), 2, "{listed}");
    let local = rows.iter().find(|row| row["kind"] == "local").unwrap();
    let parameter = rows.iter().find(|row| row["kind"] == "parameter").unwrap();
    assert_eq!(parameter["ordinal"], 0);
    assert_eq!(parameter["name"], "input");
    assert_eq!(local["type_path"], "/int");
    assert_eq!(local["size"], 4);
    assert!(local.get("first_use").is_some());
    let get = |name: &str| {
        let result = ghidra(harness)
            .args([
                "function",
                "var",
                "get",
                "edit_target",
                "--var",
                name,
                "--json",
            ])
            .with_project(test_project(), &program)
            .run();
        result.assert_success();
        result.data::<Value>()
    };
    let inferred_local = get(local["name"].as_str().unwrap());
    assert_eq!(inferred_local["decompiler"], *local);
    assert!(inferred_local["database"].is_null(), "{inferred_local}");
    let saved_parameter = get("input");
    assert_eq!(saved_parameter["database"]["name"], "input");
    assert_eq!(saved_parameter["database"]["source"], "USER_DEFINED");
    assert_eq!(list()["modification"], listed["modification"]);
    let projected = ghidra(harness)
        .args([
            "function",
            "var",
            "list",
            "edit_target",
            "--filter",
            "kind=parameter",
            "--fields",
            "name,ordinal",
            "--sort",
            "name",
            "--limit",
            "0",
            "--json",
        ])
        .with_project(test_project(), &program)
        .run();
    projected.assert_success();
    assert_eq!(
        projected.data::<Value>(),
        json!([{"name":"input","ordinal":0}])
    );
    assert_eq!(list()["modification"], listed["modification"]);

    let renamed = edit(original["name"].as_str().unwrap(), &["--name", "value"]);
    renamed.assert_success();
    let renamed: serde_json::Value = renamed.data();
    assert_eq!(renamed["kind"], "local");
    assert!(renamed["before"].is_null(), "{renamed}");
    assert_eq!(renamed["decompiler"]["name"], original["name"]);
    assert_eq!(renamed["after"]["name"], "value");
    assert_eq!(renamed["after"]["type"], "undefined4");
    assert_eq!(decompile()["variables"][0]["type"], original["type"]);
    let saved_local = get("value");
    assert_eq!(saved_local["database"], renamed["after"]);
    assert_eq!(saved_local["decompiler"]["type"], "int");
    assert_eq!(saved_local["database"]["type"], "undefined4");

    let typed = edit("value", &["--type", "uint"]);
    typed.assert_success();
    let typed: serde_json::Value = typed.data();
    assert_eq!(typed["after"]["name"], "value");
    assert_eq!(typed["after"]["type"], "uint");

    let combined = edit("value", &["--name", "buffer", "--type", "char *"]);
    combined.assert_success();
    let combined: serde_json::Value = combined.data();
    assert_eq!(combined["before"]["name"], "value");
    assert_eq!(combined["after"]["name"], "buffer");
    assert_eq!(combined["after"]["type"], "char *");
    assert_eq!(combined["after"]["storage"], combined["before"]["storage"]);

    let parameter = edit(
        "input",
        &[
            "--where",
            "kind=parameter AND ordinal=0",
            "--name",
            "count",
            "--type",
            "uint",
        ],
    );
    parameter.assert_success();
    let parameter: serde_json::Value = parameter.data();
    assert_eq!(parameter["kind"], "parameter");
    assert_eq!(parameter["after"]["name"], "count");
    assert_eq!(parameter["after"]["type"], "uint");
    let parameter = edit("count", &["--name", "length"]);
    parameter.assert_success();
    let parameter: serde_json::Value = parameter.data();
    assert_eq!(parameter["after"]["type"], "uint");
    let parameter = edit("length", &["--type", "int"]);
    parameter.assert_success();
    let parameter: serde_json::Value = parameter.data();
    assert_eq!(parameter["after"]["name"], "length");
    assert_eq!(parameter["after"]["type"], "int");

    let snapshot = list();
    let variable = snapshot["variables"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"] == "buffer")
        .unwrap();
    let selection = json!({"project":snapshot["project"], "program":snapshot["program"], "function_address":snapshot["address"],
        "modification":snapshot["modification"], "variable":variable});
    // Even a structurally identical variable must not accept a selection made
    // before an intervening program edit.
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.CommentType;
public class ChangeVariableSelectionRevision extends GhidraScript {
    public void run() {
        currentProgram.getListing().setComment(toAddr(0x1000), CommentType.EOL, "revision changed");
    }
}
"#,
            &[],
            &[],
            false,
        )
        .unwrap();
    assert_eq!(get("buffer")["decompiler"], *variable);
    let stale = client
        .send_command(
            "function_var_set",
            Some(json!({"target":"edit_target",
        "var_name":"buffer", "selection":selection, "new_name":"wrong_target"})),
        )
        .unwrap_err();
    assert!(stale.to_string().contains("stale"), "{stale}");
    let current = list();
    let valid = json!({"project":current["project"], "program":current["program"], "function_address":current["address"],
        "modification":current["modification"], "variable":variable});
    for (field, value) in [
        (
            "project",
            json!({"location":"/another-project", "name":"project"}),
        ),
        ("program", json!("/another-program")),
        ("function_address", json!("0x00001100")),
        ("modification", json!(0)),
        ("variable", json!({"name":"buffer"})),
    ] {
        let mut invalid = valid.clone();
        invalid[field] = value;
        assert!(client
            .send_command(
                "function_var_set",
                Some(json!({"target":"edit_target",
            "var_name":"buffer", "selection":invalid, "new_name":"wrong_target"}))
            )
            .is_err());
    }
    // Reads share the same snapshot validation, and an intact snapshot works.
    let refreshed = list();
    let valid = json!({"project":refreshed["project"], "program":refreshed["program"], "function_address":refreshed["address"],
        "modification":refreshed["modification"], "variable":variable});
    let selected = client
        .send_command(
            "function_var_get",
            Some(json!({"target":"edit_target",
        "var_name":"buffer", "selection":valid})),
        )
        .unwrap();
    assert_eq!(selected["decompiler"], *variable);

    let before_errors = decompile();
    for (flags, message) in [
        (vec!["--name", "collision", "--type", "float"], "conflicts"),
        (vec!["--name", "length", "--type", "float"], "conflicts"),
        (
            vec!["--name", "bad name", "--type", "float"],
            "invalid characters",
        ),
        (
            vec!["--name", "changed", "--type", "MissingType"],
            "Type not found",
        ),
        (
            vec!["--name", "changed", "--type", "void"],
            "fixed positive size",
        ),
    ] {
        let failed = edit("buffer", &flags);
        failed.assert_failure();
        let error: serde_json::Value = serde_json::from_str(&failed.stderr).unwrap();
        assert!(
            error["message"].as_str().unwrap().contains(message),
            "{error}"
        );
        assert!(
            error["detail"].get("partial_changes_saved").is_none(),
            "{error}"
        );
    }
    let missing = edit("does_not_exist", &["--name", "changed"]);
    missing.assert_failure();
    assert!(missing.stderr.contains("Variable not found"));
    // Direct bridge callers receive the same input validation as CLI callers.
    for args in [
        serde_json::json!({"target": "edit_target", "var_name": "buffer"}),
        serde_json::json!({"target": "edit_target", "var_name": "buffer", "new_name": ""}),
        serde_json::json!({"target": "edit_target", "var_name": "buffer", "new_name": "changed", "type_name": ""}),
    ] {
        assert!(client.send_command("function_var_set", Some(args)).is_err());
    }
    let after_errors = decompile();
    assert_eq!(after_errors["variables"], before_errors["variables"]);
    assert_eq!(after_errors["params"], before_errors["params"]);

    // Releasing and reopening the program must recover the saved definitions.
    client.program_close().unwrap();
    let saved = decompile();
    assert_eq!(saved["variables"], before_errors["variables"]);
    assert_eq!(saved["params"], before_errors["params"]);
    assert_eq!(saved["variables"][0]["name"], "buffer");
    assert_eq!(saved["variables"][0]["type"], "char *");
    assert_eq!(saved["params"][0]["name"], "length");
    // A DEFAULT signature's inferred parameter is discoverable without
    // committing a declaration as a side effect of list/get.
    let inferred = client
        .send_command("function_var_list", Some(json!({"target":"inferred"})))
        .unwrap();
    assert!(
        inferred["variables"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["name"] != "INCREMENT"),
        "{inferred}"
    );
    let row = inferred["variables"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["kind"] == "parameter")
        .unwrap();
    let detail = client
        .send_command(
            "function_var_get",
            Some(json!({"target":"inferred", "var_name":row["name"]})),
        )
        .unwrap();
    assert!(detail["database"].is_null(), "{detail}");
    let signature = client
        .send_command(
            "get_function",
            Some(json!({"address":"inferred", "with_signature":true})),
        )
        .unwrap();
    assert_eq!(signature["signature_details"]["params"], json!([]));
    assert_eq!(signature["signature_details"]["source"], "DEFAULT");

    let method = client
        .send_command("function_var_list", Some(json!({"target":"method"})))
        .unwrap();
    let this = method["variables"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"] == "this")
        .unwrap();
    assert_eq!(this["kind"], "parameter");
    let address = method["address"].as_str().unwrap();
    for (namespace, kind) in [("Global", "global"), ("Receiver", "class")] {
        if kind == "class" {
            ghidra(harness)
                .args(["namespace", "create", namespace, "--kind", "class"])
                .with_project(test_project(), &program)
                .run()
                .assert_success();
            ghidra(harness)
                .args([
                    "symbol",
                    "set-namespace",
                    "method",
                    "--namespace",
                    namespace,
                    "--address",
                    address,
                ])
                .with_project(test_project(), &program)
                .run()
                .assert_success();
        }
        let signature = || {
            client
                .send_command(
                    "get_function",
                    Some(json!({"address":address, "with_signature":true})),
                )
                .unwrap()
        };
        let variable = || {
            client
                .send_command(
                    "function_var_get",
                    Some(json!({"target":address, "var_name":"this"})),
                )
                .unwrap()
        };
        let before = signature();
        let this = variable();
        let symbol_before = client.symbol_get_by_name("method").unwrap();
        assert_eq!(this["database"]["auto_parameter"], "THIS");
        let rejected = ghidra(harness)
            .args([
                "function", "var", "set", address, "--var", "this", "--name", "object", "--type",
                "char *", "--json",
            ])
            .with_project(test_project(), &program)
            .run();
        rejected.assert_failure();
        let error: Value = serde_json::from_str(&rejected.stderr).unwrap();
        let message = error["message"].as_str().unwrap();
        for hint in [
            "auto-parameter",
            "class namespace and calling convention",
            "namespace create --kind class",
            "symbol set-namespace",
            "--namespace",
            "--address",
        ] {
            assert!(message.contains(hint), "{error}");
        }
        let detail = &error["detail"];
        assert_eq!(detail["function"], "method");
        assert_eq!(detail["address"], address);
        assert_eq!(detail["program"], method["program"]);
        assert_eq!(detail["namespace"], json!({"path":namespace, "kind":kind}));
        assert_eq!(detail["calling_convention"], before["calling_convention"]);
        assert_eq!(detail["parameter"], this["database"]);
        assert_eq!(detail["rolled_back"], true);
        assert_eq!(signature(), before);
        assert_eq!(variable(), this);
        assert_eq!(client.symbol_get_by_name("method").unwrap(), symbol_before);
    }
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&program).unwrap();
}

#[test]
#[serial]
fn parameter_edits_roll_back_when_native_naming_changes_the_requested_name() {
    require_ghidra!();
    let client = harness().client().unwrap();
    let program = format!("variable-name-{}", uuid::Uuid::new_v4());
    client
        .script_run_source(
            include_str!("../fixtures/types/CreateVariableTestProgram.java"),
            std::slice::from_ref(&program),
            &[],
            false,
        )
        .unwrap();
    super::common::with_temporary_program(&client, &program, TEST_PROGRAM, || {
        let state = || {
            client
                .send_command(
                    "get_function",
                    Some(
                        json!({"address":"edit_target", "with_signature":true, "with_frame":true}),
                    ),
                )
                .unwrap()
        };
        let before = state();
        let failed = client
            .send_command(
                "function_var_set",
                Some(json!({"target":"edit_target", "var_name":"input",
                    "new_name":"param_17", "type_name":"undefined8"})),
            )
            .unwrap_err();
        let error = failed
            .downcast_ref::<ghidra_cli::ipc::protocol::BridgeCommandError>()
            .unwrap();
        assert!(error.to_string().contains("param_17"), "{error:?}");
        assert_eq!(error.detail["rolled_back"], true, "{error:?}");
        assert_eq!(state(), before);
        client.program_close().unwrap();
        client.open_program(&program).unwrap();
        assert_eq!(state(), before);
    });
}
