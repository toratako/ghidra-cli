use super::{ghidra, harness, test_project, TEST_PROGRAM};
use serde_json::{json, Value};
use serial_test::serial;

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
            include_str!("../function_variables/CreateVariableTestProgram.java"),
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
            "--filter",
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
    let selection = json!({"program":snapshot["program"], "function_address":snapshot["address"],
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
    let valid = json!({"program":current["program"], "function_address":current["address"],
        "modification":current["modification"], "variable":variable});
    for (field, value) in [
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
    let valid = json!({"program":refreshed["program"], "function_address":refreshed["address"],
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

    let before = client
        .send_command(
            "get_function",
            Some(json!({"address":"method", "with_signature":true})),
        )
        .unwrap();
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
    let this = client
        .send_command(
            "function_var_get",
            Some(json!({"target":"method", "var_name":"this"})),
        )
        .unwrap();
    assert_eq!(this["database"]["auto_parameter"], "THIS");
    let rejected = client
        .send_command(
            "function_var_set",
            Some(json!({"target":"method", "var_name":"this",
        "new_name":"object", "type_name":"char *"})),
        )
        .unwrap_err();
    assert!(
        rejected.to_string().contains("auto-parameter"),
        "{rejected}"
    );
    let after = client
        .send_command(
            "get_function",
            Some(json!({"address":"method", "with_signature":true})),
        )
        .unwrap();
    assert_eq!(after, before);
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&program).unwrap();
}
