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
    client
        .script_run_source(
            include_str!("../fixtures/symbols/ScopedSymbolFixture.java"),
            &[addresses[0].clone(), name.clone()],
            &[],
            false,
        )
        .unwrap();
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
fn symbol_rename_rejects_replaced_dynamic_targets() {
    require_ghidra!();
    let client = harness().client().unwrap();
    let program = super::deletion::create_symbol_fixture_program();
    crate::common::with_temporary_program(&client, &program, TEST_PROGRAM, || {
        client
            .script_run_source(
                include_str!("../fixtures/symbols/CreateDynamicSymbol.java"),
                &[],
                &[],
                false,
            )
            .unwrap();
        let target = client.symbol_get("0x1010").unwrap()["symbols"][0].clone();
        let name = target["name"].as_str().unwrap();
        client.symbol_create_label("0x1010", "replacement").unwrap();
        let before = client.symbol_get("0x1010").unwrap();
        let error = client
            .symbol_rename_targets(name, "must_not_recreate", std::slice::from_ref(&target))
            .expect_err("a replaced dynamic symbol cannot remain a valid rename target");
        assert!(error.to_string().contains("Stale"), "{error:#}");
        assert!(client.symbol_get_by_name("must_not_recreate").is_err());
        assert_eq!(client.symbol_get("0x1010").unwrap(), before);
        client.program_close().unwrap();
        client.open_program(&program).unwrap();
        assert_eq!(client.symbol_get("0x1010").unwrap(), before);
    });
}

#[test]
#[serial]
fn symbol_rename_rolls_back_native_generated_name_substitutions() {
    require_ghidra!();
    let client = harness().client().unwrap();
    let program = super::deletion::create_symbol_fixture_program();
    crate::common::with_temporary_program(&client, &program, TEST_PROGRAM, || {
        client
            .script_run_source(
                include_str!("../fixtures/symbols/RenameIdentityFixture.java"),
                &[],
                &[],
                false,
            )
            .unwrap();
        let before = client.symbol_get_by_name("rename_selected").unwrap();
        let targets = before["symbols"].as_array().unwrap();
        let label = targets.iter().find(|row| row["type"] == "Label").unwrap();
        let parameter = targets
            .iter()
            .find(|row| row["type"] == "Parameter")
            .unwrap();
        let function_before = client
            .send_command(
                "get_function",
                Some(serde_json::json!({"address": "0x1020"})),
            )
            .unwrap();
        // Ghidra substitutes param_1 for param_99 on the first parameter.
        // The preceding label edit must be rolled back with that substitution.
        let error = client
            .symbol_rename_targets(
                "rename_selected",
                "param_99",
                &[label.clone(), parameter.clone()],
            )
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("did not retain the requested symbol name"),
            "{error:#}"
        );
        let detail = &error
            .downcast_ref::<ghidra_cli::ipc::protocol::BridgeCommandError>()
            .unwrap()
            .detail;
        assert_eq!(detail["rolled_back"], true);
        assert!(detail.get("partial_changes_saved").is_none());
        assert_eq!(
            client.symbol_get_by_name("rename_selected").unwrap(),
            before
        );
        assert!(client.symbol_get_by_name("param_99").is_err());
        client.program_close().unwrap();
        client.open_program(&program).unwrap();
        assert_eq!(
            client.symbol_get_by_name("rename_selected").unwrap(),
            before
        );
        assert_eq!(
            client
                .send_command(
                    "get_function",
                    Some(serde_json::json!({"address": "0x1020"}))
                )
                .unwrap(),
            function_before
        );

        client
            .symbol_rename_targets(
                "rename_selected",
                "renamed_parameter",
                std::slice::from_ref(parameter),
            )
            .unwrap();
        let renamed = client.symbol_get_by_name("renamed_parameter").unwrap();
        assert_eq!(renamed["symbols"][0]["id"], parameter["id"]);
        assert_eq!(
            client.symbol_get_by_name("rename_selected").unwrap()["symbols"],
            serde_json::json!([label])
        );

        // Naming a generated label persists it under a fresh native identity.
        let dynamic = client.symbol_get("0x1030").unwrap()["symbols"][0].clone();
        client
            .symbol_rename_targets(
                dynamic["name"].as_str().unwrap(),
                "renamed_dynamic",
                std::slice::from_ref(&dynamic),
            )
            .unwrap();
        assert_eq!(
            client.symbol_get_by_name("renamed_dynamic").unwrap()["symbols"][0]["address"],
            "0x00001030"
        );
    });
}

#[test]
#[serial]
fn symbol_lookup_round_trips_generated_variable_names() {
    require_ghidra!();
    let client = harness().client().unwrap();
    let program = super::deletion::create_symbol_fixture_program();
    crate::common::with_temporary_program(&client, &program, TEST_PROGRAM, || {
        client
            .script_run_source(
                include_str!("../fixtures/symbols/RenameIdentityFixture.java"),
                &[],
                &[],
                false,
            )
            .unwrap();
        let listed = client.symbol_list(None, None, None).unwrap();
        let generated: Vec<_> = listed["symbols"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["namespace"] == "generated_owner" && row["source"] == "DEFAULT")
            .collect();
        assert_eq!(generated.len(), 2, "{listed}");
        let mut renamed = Vec::new();
        for (index, target) in generated.into_iter().enumerate() {
            let name = target["name"].as_str().unwrap();
            let found = client.symbol_get_by_name(name).unwrap();
            assert!(
                found["symbols"].as_array().unwrap().contains(target),
                "{found}"
            );
            assert_eq!(client.symbol_get(name).unwrap(), found);
            if name == "param_1" {
                // An indexed label with the same name must not hide the parameter.
                assert_eq!(found["symbols"].as_array().unwrap().len(), 2, "{found}");
            }
            let new_name = format!("named_generated_{index}");
            client
                .symbol_rename_targets(name, &new_name, std::slice::from_ref(target))
                .unwrap();
            let after = client.symbol_get_by_name(&new_name).unwrap();
            assert_eq!(after["symbols"][0]["id"], target["id"]);
            renamed.push((new_name, after));
        }
        client.program_close().unwrap();
        client.open_program(&program).unwrap();
        for (name, expected) in renamed {
            assert_eq!(client.symbol_get_by_name(&name).unwrap(), expected);
        }
    });
}

#[test]
#[serial]
fn generated_external_names_resolve_the_exact_reference_target() {
    require_ghidra!();
    let client = harness().client().unwrap();
    let program = super::deletion::create_symbol_fixture_program();
    crate::common::with_temporary_program(&client, &program, TEST_PROGRAM, || {
        client
            .script_run_source(
                include_str!("../fixtures/symbols/GeneratedExternalNames.java"),
                &[],
                &[],
                false,
            )
            .unwrap();
        let listed = client.symbol_list(None, None, None).unwrap();
        let targets: Vec<_> = listed["symbols"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["namespace"] == "generated_library" && row["source"] == "DEFAULT")
            .cloned()
            .collect();
        assert_eq!(targets.len(), 2, "{listed}");
        let function = targets
            .iter()
            .find(|row| row["type"] == "Function")
            .unwrap();
        let name = function["name"].as_str().unwrap();
        let memory = client
            .send_command(
                "read_memory",
                Some(serde_json::json!({"address": "0x1040", "size": 1})),
            )
            .unwrap();
        let error = client
            .send_command(
                "memory_write",
                Some(serde_json::json!({"address": name, "hex": "90"})),
            )
            .expect_err("a generated external name must make the local label ambiguous");
        assert!(error.to_string().contains("Ambiguous"), "{error:#}");
        assert_eq!(
            client
                .send_command(
                    "read_memory",
                    Some(serde_json::json!({"address": "0x1040", "size": 1}))
                )
                .unwrap(),
            memory
        );
        assert_eq!(client.symbol_list(None, None, None).unwrap(), listed);
        client.program_close().unwrap();
        client.open_program(&program).unwrap();
        assert_eq!(
            client
                .send_command(
                    "read_memory",
                    Some(serde_json::json!({"address": "0x1040", "size": 1}))
                )
                .unwrap(),
            memory
        );
        assert_eq!(client.symbol_list(None, None, None).unwrap(), listed);
        let candidates = client.symbol_get_by_name(name).unwrap();
        let label = candidates["symbols"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["namespace"] == "Global")
            .unwrap();
        client
            .symbol_delete_targets(name, std::slice::from_ref(label))
            .unwrap();
        for target in &targets {
            let name = target["name"].as_str().unwrap();
            let address = target["address"].as_str().unwrap();
            let expected = client.xrefs_to(address.to_owned()).unwrap();
            assert_eq!(expected["count"], 1);
            for selected in [name.to_owned(), format!("generated_library::{name}")] {
                assert_eq!(
                    client
                        .xrefs_to(selected.clone())
                        .unwrap_or_else(|error| panic!("generated external {selected}: {error:#}")),
                    expected
                );
            }
            if target["type"] == "Function" {
                let qualified = format!("generated_library::{name}");
                let before = client
                    .send_command(
                        "get_function",
                        Some(serde_json::json!({"address": address})),
                    )
                    .unwrap();
                assert_eq!(
                    client
                        .send_command(
                            "get_function",
                            Some(serde_json::json!({"address": qualified}))
                        )
                        .unwrap(),
                    before
                );
                client
                    .send_command(
                        "function_set_noreturn",
                        Some(serde_json::json!({"target": qualified, "value": true})),
                    )
                    .unwrap();
                assert_eq!(
                    client
                        .send_command(
                            "get_function",
                            Some(serde_json::json!({"address": address}))
                        )
                        .unwrap()["no_return"],
                    true
                );
                client.program_close().unwrap();
                client.open_program(&program).unwrap();
                assert_eq!(
                    client
                        .send_command("get_function", Some(serde_json::json!({"address": name})))
                        .unwrap()["no_return"],
                    true
                );
            }
        }
    });
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
    client
        .script_run_source(
            include_str!("../fixtures/symbols/DuplicateFunctionFixture.java"),
            &[
                addresses[0].clone(),
                addresses[1].clone(),
                duplicate.clone(),
            ],
            &[],
            false,
        )
        .unwrap();
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
            include_str!("../fixtures/symbols/RestoreFunctionFixture.java"),
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
