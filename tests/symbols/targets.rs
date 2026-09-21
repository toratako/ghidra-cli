use super::{ghidra, harness, test_project, TEST_PROGRAM};
use crate::common::{get_function_address, get_function_addresses};
use serial_test::serial;

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
            .args(["symbol", "create-label", &address, name])
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
    client.symbol_create_label(&addresses[0], hex_name).unwrap();
    client
        .symbol_create_label(&addresses[0], &explicit_address)
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
    let valid_targets = client.symbol_get(&name).unwrap()["symbols"]
        .as_array()
        .unwrap()
        .clone();
    for command in ["symbol_delete", "symbol_rename"] {
        for targets in [
            None,
            Some(serde_json::Value::Null),
            Some(serde_json::json!({})),
            Some(serde_json::json!([])),
            Some(serde_json::json!([valid_targets[0], valid_targets[0]])),
        ] {
            let mut args = serde_json::json!({
                "name": name,
                "old_name": name,
                "new_name": "must_not_rename",
            });
            if let Some(targets) = targets {
                args["targets"] = targets;
            }
            client.send_command(command, Some(args)).unwrap_err();
            assert_eq!(
                client.symbol_get(&name).unwrap()["symbols"],
                serde_json::json!(valid_targets)
            );
        }
    }
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
