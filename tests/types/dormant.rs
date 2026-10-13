//! Type edits preserve dormant own ABIs independently of an active thunk's owner view.
use super::{create_type_edit_program, harness, type_command, TEST_PROGRAM};
use ghidra_cli::ipc::client::BridgeClient;
use serde_json::{json, Value};
use serial_test::serial;

fn snapshot(client: &BridgeClient) -> Value {
    let result = client
        .script_run_source(
            include_str!("DormantTypeMutationFixture.java"),
            &["read".to_owned()],
            &[],
            false,
        )
        .unwrap();
    serde_json::from_str(result["stdout"].as_str().unwrap().trim()).unwrap()
}

fn inventory(program: &str) -> Value {
    let result = type_command(program, &["list", "--limit", "0", "--sort", "path"]);
    result.assert_success();
    result.data()
}

fn with_fixture(check: impl FnOnce(&BridgeClient, &str)) {
    let program = create_type_edit_program("x86:LE:32:default");
    let client = harness().client().unwrap();
    super::common::with_temporary_program(&client, &program, TEST_PROGRAM, || {
        client
            .script_run_source(
                include_str!("DormantTypeMutationFixture.java"),
                &["create".to_owned()],
                &[],
                false,
            )
            .unwrap();
        check(&client, &program);
    });
}

fn reopen(client: &BridgeClient, program: &str) {
    client.program_close().unwrap();
    client.open_program(program).unwrap();
}

fn clear(client: &BridgeClient, name: &str) {
    client
        .send_command("function_clear_thunk", Some(json!({"target": name})))
        .unwrap();
}

fn set(client: &BridgeClient, name: &str, owner: &str) {
    client
        .send_command(
            "function_set_thunk",
            Some(json!({"target": name, "thunk_target": owner})),
        )
        .unwrap();
}

fn all_valid(abi: &Value) {
    for variable in abi["variables"].as_array().unwrap() {
        assert_eq!(variable["valid"], true, "{variable}");
    }
}

fn automatic_this(abi: &Value) -> &Value {
    abi["variables"]
        .as_array()
        .unwrap()
        .iter()
        .find(|value| value["auto"] == true && value["name"] == "this")
        .unwrap_or_else(|| panic!("Missing automatic this parameter: {abi}"))
}

#[test]
#[serial]
fn type_growth_rejects_each_dormant_return_parameter_and_local_independently() {
    require_ghidra!();
    with_fixture(|client, program| {
        let mut accepted = Vec::new();
        for operation in ["Resize", "Field", "Import"] {
            for kind in ["Return", "Parameter", "Local"] {
                let name = format!("{operation}{kind}");
                let path = format!("/Dormant/{name}");
                let before = snapshot(client);
                let types = inventory(program);
                all_valid(&before["own"][&name]);
                let declaration = format!("struct {name} {{ long long grown; }};");
                let args = match operation {
                    "Resize" => vec!["resize", &path, "--size", "8"],
                    "Field" => vec!["field", "append", &path, "--type", "int", "--name", "added"],
                    _ => vec!["import-c", "--category", "/Dormant", "--code", &declaration],
                };
                let result = type_command(program, &args);
                if result.exit_code == 0 {
                    let after = snapshot(client);
                    let invalid: Vec<_> = after["own"][&name]["variables"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .filter(|variable| variable["valid"] == false)
                        .cloned()
                        .collect();
                    accepted.push(format!("{name}: {invalid:?}"));
                    continue;
                }
                result.assert_failure();
                let error: Value = serde_json::from_str(&result.stderr).unwrap();
                assert_eq!(error["detail"]["rolled_back"], true, "{error}");
                assert!(
                    error["detail"].get("partial_changes_saved").is_none(),
                    "{error}"
                );
                for persisted in [false, true] {
                    if persisted {
                        reopen(client, program);
                    }
                    assert_eq!(snapshot(client), before, "{name}, reopened={persisted}");
                    assert_eq!(inventory(program), types, "{name}");
                }
                // Expose the actual live dormant definition after failure, then
                // verify its saved identity and restore the original graph.
                clear(client, &name);
                let exposed = snapshot(client);
                assert_eq!(exposed["live"][&name]["visible"], before["own"][&name]);
                all_valid(&exposed["live"][&name]["visible"]);
                reopen(client, program);
                assert_eq!(snapshot(client), exposed);
                set(client, &name, &format!("{name}Owner"));
                assert_eq!(snapshot(client), before);
            }
        }
        assert!(
            accepted.is_empty(),
            "Dormant own definitions became invalid: {accepted:#?}"
        );
    });
}

#[test]
#[serial]
fn safe_dormant_type_changes_preserve_mixed_abis_graphs_and_existing_invalid_values() {
    require_ghidra!();
    with_fixture(|client, program| {
        for (name, size) in [
            ("ModeCC", "2"),
            ("ModeCD", "2"),
            ("ModeDC", "8"),
            ("ModeDD", "8"),
        ] {
            let before = snapshot(client);
            let owner = format!("{name}Owner");
            let path = format!("/Dormant/{name}Value");
            let result = type_command(program, &["resize", &path, "--size", size]);
            result.assert_success();
            let after = snapshot(client);
            assert_eq!(
                after["live"][name]["direct_id"],
                before["live"][name]["direct_id"]
            );
            assert_eq!(after["live"][&owner], before["live"][&owner]);
            assert_eq!(after["own"][&owner], before["own"][&owner]);
            all_valid(&after["own"][name]);
            clear(client, name);
            let exposed = snapshot(client);
            assert_eq!(exposed["live"][name]["visible"], after["own"][name]);
            all_valid(&exposed["live"][name]["visible"]);
            reopen(client, program);
            assert_eq!(snapshot(client), exposed);
            set(client, name, &owner);
            assert_eq!(snapshot(client), after);
        }
        let before = snapshot(client);
        assert_eq!(before["live"]["ClassSource"]["class_namespace"], true);
        assert_eq!(before["live"]["ClassOwner"]["class_namespace"], true);
        assert_ne!(
            before["live"]["ClassSource"]["namespace"],
            before["live"]["ClassOwner"]["namespace"]
        );
        assert_eq!(before["own"]["ClassSource"]["convention"], "__thiscall");
        assert_eq!(before["own"]["ClassSource"]["custom"], false);
        let own_this = automatic_this(&before["own"]["ClassSource"]);
        let visible_this = automatic_this(&before["live"]["ClassSource"]["visible"]);
        assert!(
            own_this["type"]
                .as_str()
                .unwrap()
                .contains("DormantWrapper"),
            "{own_this}"
        );
        assert!(
            visible_this["type"]
                .as_str()
                .unwrap()
                .contains("DormantWrapper"),
            "{visible_this}"
        );
        let owner_this = automatic_this(&before["own"]["ClassOwner"]);
        assert!(
            owner_this["type"]
                .as_str()
                .unwrap()
                .contains("DormantTarget"),
            "{owner_this}"
        );
        type_command(program, &["resize", "/Dormant/ClassValue", "--size", "8"]).assert_success();
        let after = snapshot(client);
        all_valid(&after["own"]["ClassSource"]);
        assert_eq!(after["live"]["ClassSource"], before["live"]["ClassSource"]);
        assert_eq!(after["live"]["ClassOwner"], before["live"]["ClassOwner"]);
        assert_eq!(after["own"]["ClassOwner"], before["own"]["ClassOwner"]);
        assert_eq!(automatic_this(&after["own"]["ClassSource"]), own_this);
        clear(client, "ClassSource");
        let exposed = snapshot(client);
        assert_eq!(
            exposed["live"]["ClassSource"]["visible"],
            after["own"]["ClassSource"]
        );
        assert_eq!(
            exposed["live"]["ClassSource"]["namespace"],
            before["live"]["ClassSource"]["namespace"]
        );
        all_valid(&exposed["live"]["ClassSource"]["visible"]);
        reopen(client, program);
        assert_eq!(snapshot(client), exposed);
        set(client, "ClassSource", "ClassOwner");
        assert_eq!(snapshot(client), after);
        for args in [
            vec!["resize", "/Dormant/DynamicValue", "--size", "8"],
            vec![
                "field",
                "append",
                "/Dormant/DynamicValue",
                "--type",
                "int",
                "--name",
                "added",
            ],
            vec![
                "import-c",
                "--category",
                "/Dormant",
                "--code",
                "struct DynamicValue { long long lanes[2]; };",
            ],
        ] {
            let before = snapshot(client);
            type_command(program, &args).assert_success();
            let after = snapshot(client);
            all_valid(&after["own"]["Dynamic"]);
            assert_eq!(
                after["live"]["DynamicOwner"],
                before["live"]["DynamicOwner"]
            );
            assert_eq!(after["own"]["DynamicOwner"], before["own"]["DynamicOwner"]);
            reopen(client, program);
            assert_eq!(snapshot(client), after);
        }
        for (path, size, function) in [
            ("/Dormant/ChainValue", "2", "Chained"),
            ("/Dormant/PointerValue", "16", "Pointer"),
            ("/Dormant/PreexistingInvalid", "12", "Preexisting"),
            ("/Dormant/Unreferenced", "64", ""),
        ] {
            let before = snapshot(client);
            type_command(program, &["resize", path, "--size", size]).assert_success();
            let after = snapshot(client);
            if function == "Pointer" || function.is_empty() {
                assert_eq!(after, before);
            } else {
                assert_eq!(
                    after["live"][function]["direct_id"],
                    before["live"][function]["direct_id"]
                );
                assert_eq!(
                    after["live"]["ExternalOwner"],
                    before["live"]["ExternalOwner"]
                );
                assert_eq!(
                    after["own"]["ExternalOwner"],
                    before["own"]["ExternalOwner"]
                );
            }
            if function == "Chained" {
                all_valid(&after["own"][function]);
            }
            if function == "Preexisting" {
                assert!(before["own"][function]["variables"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|v| v["valid"] == false));
                assert!(after["own"][function]["variables"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|v| v["valid"] == false));
            }
            reopen(client, program);
            assert_eq!(snapshot(client), after);
        }
    });
}

#[test]
#[serial]
fn dormant_custom_local_growth_rejects_even_when_owner_has_dynamic_storage() {
    require_ghidra!();
    with_fixture(|client, program| {
        let before = snapshot(client);
        let types = inventory(program);
        assert_eq!(before["own"]["ModeCD"]["custom"], true);
        assert_eq!(before["own"]["ModeCDOwner"]["custom"], false);
        assert_eq!(before["live"]["ModeCD"]["visible"]["custom"], false);
        all_valid(&before["own"]["ModeCD"]);
        all_valid(&before["live"]["ModeCD"]["visible"]);
        let result = type_command(program, &["resize", "/Dormant/ModeCDValue", "--size", "8"]);
        result.assert_failure();
        let error: Value = serde_json::from_str(&result.stderr).unwrap();
        assert_eq!(error["detail"]["rolled_back"], true, "{error}");
        for persisted in [false, true] {
            if persisted {
                reopen(client, program);
            }
            assert_eq!(snapshot(client), before);
            assert_eq!(inventory(program), types);
        }
        clear(client, "ModeCD");
        let exposed = snapshot(client);
        assert_eq!(
            exposed["live"]["ModeCD"]["visible"],
            before["own"]["ModeCD"]
        );
        all_valid(&exposed["live"]["ModeCD"]["visible"]);
        reopen(client, program);
        assert_eq!(snapshot(client), exposed);
        set(client, "ModeCD", "ModeCDOwner");
        assert_eq!(snapshot(client), before);
    });
}

#[test]
#[serial]
fn c_kind_replacement_preserves_dormant_return_type_identity() {
    require_ghidra!();
    with_fixture(|client, program| {
        let before = snapshot(client);
        let types = inventory(program);
        let result = type_command(
            program,
            &[
                "import-c",
                "--category",
                "/Dormant",
                "--code",
                "union KindValue { int replacement; };",
            ],
        );
        if result.exit_code == 0 {
            let after = snapshot(client);
            panic!("Kind replacement substituted dormant return despite native validity: before={}, after={}",
                before["own"]["KindReturn"], after["own"]["KindReturn"]);
        }
        result.assert_failure();
        let error: Value = serde_json::from_str(&result.stderr).unwrap();
        assert_eq!(error["detail"]["rolled_back"], true, "{error}");
        for persisted in [false, true] {
            if persisted {
                reopen(client, program);
            }
            assert_eq!(snapshot(client), before);
            assert_eq!(inventory(program), types);
        }
        clear(client, "KindReturn");
        let exposed = snapshot(client);
        assert_eq!(
            exposed["live"]["KindReturn"]["visible"],
            before["own"]["KindReturn"]
        );
        reopen(client, program);
        assert_eq!(snapshot(client), exposed);
    });
}
