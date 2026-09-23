//! Native namespace hierarchy, stable symbol moves, primary labels and class ABI effects.

#[macro_use]
mod common;

use common::helpers::ghidra;
use common::{ensure_test_project, test_project, DaemonTestHarness, FIXTURE_PROGRAM};
use ghidra_cli::ipc::client::BridgeClient;
use serde_json::{json, Value};
use serial_test::serial;
use std::sync::OnceLock;

static HARNESS: OnceLock<DaemonTestHarness> = OnceLock::new();

fn harness() -> &'static DaemonTestHarness {
    HARNESS.get_or_init(|| {
        ensure_test_project(test_project(), FIXTURE_PROGRAM);
        DaemonTestHarness::new(test_project(), FIXTURE_PROGRAM).expect("start namespace bridge")
    })
}

fn with_fixture(test: impl FnOnce(&BridgeClient, &str)) {
    let client = harness().client().unwrap();
    let program = format!("namespaces-{}", uuid::Uuid::new_v4());
    client
        .script_run_source(
            include_str!("namespaces/CreateNamespaceFixture.java"),
            std::slice::from_ref(&program),
            &[],
            false,
        )
        .unwrap();
    client.open_program(&program).unwrap();
    let checked =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| test(&client, &program)));
    client.open_program(FIXTURE_PROGRAM).unwrap();
    client.program_delete(&program).unwrap();
    if let Err(panic) = checked {
        std::panic::resume_unwind(panic);
    }
}

fn command(program: &str, args: &[&str]) -> Value {
    let result = ghidra(harness())
        .args(args.iter().copied())
        .with_project(test_project(), program)
        .arg("--json")
        .run();
    result.assert_success();
    result.data()
}

fn symbol(client: &BridgeClient, name: &str) -> Value {
    let found = client.symbol_get_by_name(name).unwrap();
    assert_eq!(found["symbols"].as_array().unwrap().len(), 1, "{found}");
    found["symbols"][0].clone()
}

fn move_symbol(client: &BridgeClient, target: &Value, namespace: Option<&str>) -> Value {
    client
        .send_command(
            "symbol_set_namespace",
            Some(json!({"name":target["name"], "targets":[target],
                "namespace":namespace, "global":namespace.is_none()})),
        )
        .unwrap()
}

fn reference_state(client: &BridgeClient) -> String {
    client.script_run_source(r#"
import ghidra.app.script.GhidraScript;
public class ReadNamespaceReference extends GhidraScript {
    public void run() {
        var reference = currentProgram.getReferenceManager().getReference(toAddr(0x1000), toAddr(0x1010), 0);
        println(reference.getSymbolID() + ":" + reference.getFromAddress() + ":" + reference.getToAddress()
            + ":" + reference.getReferenceType() + ":" + reference.getSource() + ":" + reference.isPrimary());
    }
}
"#, &[], &[], false).unwrap()["stdout"].as_str().unwrap().trim().to_owned()
}

#[test]
#[serial]
fn namespace_hierarchy_is_exact_and_creation_never_converts_existing_kinds() {
    require_ghidra!();
    with_fixture(|client, program| {
        let root = command(program, &["namespace", "create", "app"]);
        assert_eq!(root["path"], "app");
        assert_eq!(root["kind"], "namespace");
        assert_eq!(root["parent"], Value::Null);
        let class = command(
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
        assert_eq!(class["path"], "app::Widget");
        assert_eq!(class["parent"], "app");
        assert_eq!(class["kind"], "class");
        let repeated = command(
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
        assert_eq!(repeated["id"], class["id"]);
        assert_eq!(repeated["status"], "unchanged");
        command(
            program,
            &["namespace", "create", "nested", "--parent", "app::Widget"],
        );
        command(
            program,
            &["namespace", "create", "Widget", "--parent", "right"],
        );
        let before = client.send_command("namespace_list", None).unwrap();
        for args in [
            vec!["namespace", "get", "Widget"],
            vec!["namespace", "get", "Widget::nested"],
            vec!["namespace", "create", "Widget", "--parent", "app"],
            vec![
                "namespace",
                "create",
                "child",
                "--parent",
                "missing::parent",
            ],
            vec!["namespace", "create", ""],
            vec!["namespace", "get", "fixture_library"],
        ] {
            ghidra(harness())
                .args(args)
                .with_project(test_project(), program)
                .run()
                .assert_failure();
            assert_eq!(client.send_command("namespace_list", None).unwrap(), before);
        }
        let listed = command(program, &["namespace", "list", "--filter", "kind='class'"]);
        assert_eq!(listed.as_array().unwrap().len(), 1);
        assert_eq!(listed[0]["id"], class["id"]);
        client.program_close().unwrap();
        client.open_program(program).unwrap();
        assert_eq!(client.send_command("namespace_list", None).unwrap(), before);
        let reopened = command(program, &["namespace", "get", "app::Widget"]);
        assert_eq!(reopened["id"], class["id"]);
    });
}

#[test]
#[serial]
fn namespace_paths_round_trip_native_templates_and_reject_ambiguous_native_boundaries() {
    require_ghidra!();
    with_fixture(|client, program| {
        client
            .script_run_source(
                include_str!("namespaces/CreateNamespacePaths.java"),
                &[],
                &[],
                false,
            )
            .unwrap();
        let listed = client.send_command("namespace_list", None).unwrap();
        let ambiguous: Vec<_> = listed["namespaces"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["path"] == "a::b")
            .cloned()
            .collect();
        assert_eq!(ambiguous.len(), 2);
        assert_ne!(ambiguous[0]["id"], ambiguous[1]["id"]);
        assert_ne!(ambiguous[0]["parent"], ambiguous[1]["parent"]);
        for row in listed["namespaces"].as_array().unwrap() {
            if row["path"] == "a::b" {
                continue;
            }
            let found = client
                .send_command("namespace_get", Some(json!({"path":row["path"]})))
                .unwrap();
            assert_eq!(found, *row);
        }
        let template = command(program, &["namespace", "get", "std::vector<ns::Item>"]);
        assert_eq!(template["name"], "vector<ns::Item>");
        let repeated = command(
            program,
            &[
                "namespace",
                "create",
                "vector<ns::Item>",
                "--parent",
                "std",
                "--kind",
                "class",
            ],
        );
        assert_eq!(repeated["status"], "unchanged");
        assert_eq!(repeated["id"], template["id"]);
        let child = command(
            program,
            &[
                "namespace",
                "create",
                "iterator<ns::Item>",
                "--parent",
                "std::vector<ns::Item>",
            ],
        );
        assert_eq!(
            command(
                program,
                &[
                    "namespace",
                    "get",
                    "std::vector<ns::Item>::iterator<ns::Item>"
                ]
            )["id"],
            child["id"]
        );
        assert!(client
            .send_command("namespace_get", Some(json!({"path":"vector<ns::Item>"})))
            .is_err());

        let target = symbol(client, "first_label");
        let flat_marker = symbol(client, "flat_marker");
        let nested_marker = symbol(client, "nested_marker");
        let before = client.send_command("namespace_list", None).unwrap();
        for (operation, args) in [
            ("namespace_get", json!({"path":"a::b"})),
            ("namespace_create", json!({"name":"child", "parent":"a::b"})),
            (
                "symbol_set_namespace",
                json!({"name":target["name"], "targets":[target], "namespace":"a::b"}),
            ),
        ] {
            let error = client.send_command(operation, Some(args)).unwrap_err();
            let error = error
                .downcast_ref::<ghidra_cli::ipc::protocol::BridgeCommandError>()
                .unwrap();
            assert!(
                error.to_string().contains("Ambiguous namespace path"),
                "{error}"
            );
            let candidates = error.detail["candidates"].as_array().unwrap();
            assert_eq!(candidates.len(), 2);
            assert!(ambiguous.iter().all(|row| candidates.contains(row)));
            assert_eq!(client.send_command("namespace_list", None).unwrap(), before);
            assert_eq!(symbol(client, "first_label"), target);
            assert_eq!(symbol(client, "flat_marker"), flat_marker);
            assert_eq!(symbol(client, "nested_marker"), nested_marker);
        }
        let moved = move_symbol(client, &target, Some("std::vector<ns::Item>"));
        assert_eq!(moved["after"]["id"], target["id"]);
        assert_eq!(moved["after"]["namespace"], "std::vector<ns::Item>");

        // Both orders of flat/nested creation must reject a new ambiguous path.
        command(program, &["namespace", "create", "left::child"]);
        command(program, &["namespace", "create", "branch"]);
        command(
            program,
            &["namespace", "create", "leaf", "--parent", "branch"],
        );
        let before = client.send_command("namespace_list", None).unwrap();
        for args in [
            json!({"name":"child", "parent":"left"}),
            json!({"name":"branch::leaf"}),
        ] {
            let error = client
                .send_command("namespace_create", Some(args))
                .unwrap_err();
            assert!(
                error.to_string().contains("Ambiguous namespace path"),
                "{error:#}"
            );
            assert_eq!(client.send_command("namespace_list", None).unwrap(), before);
        }
        client.program_close().unwrap();
        client.open_program(program).unwrap();
        assert_eq!(symbol(client, "first_label"), moved["after"]);
        assert_eq!(
            command(program, &["namespace", "get", "std::vector<ns::Item>"])["id"],
            template["id"]
        );
        assert!(client
            .send_command("namespace_get", Some(json!({"path":"a::b"})))
            .is_err());
    });
}

#[test]
#[serial]
fn symbol_moves_preserve_identity_references_and_reject_ambiguous_stale_or_conflicting_targets() {
    require_ghidra!();
    with_fixture(|client, program| {
        command(program, &["namespace", "create", "destination"]);
        let original = client.symbol_get_by_name("shared").unwrap();
        let targets = original["symbols"].as_array().unwrap();
        let selected = targets
            .iter()
            .find(|row| row["namespace"] == "left")
            .unwrap();
        let unaffected = targets
            .iter()
            .find(|row| row["namespace"] == "right")
            .unwrap();
        let references = reference_state(client);
        ghidra(harness())
            .args([
                "symbol",
                "set-namespace",
                "shared",
                "--namespace",
                "destination",
                "--address",
                "0x1010",
            ])
            .with_project(test_project(), program)
            .run()
            .assert_failure()
            .assert_stderr_contains("matches 2 symbols");
        for invalid in [json!(targets), json!([{ "id": selected["id"] }])] {
            let error = client
                .send_command(
                    "symbol_set_namespace",
                    Some(json!({"name":"shared", "targets":invalid,
                "namespace":"destination"})),
                )
                .unwrap_err();
            assert!(!error.to_string().is_empty());
            assert_eq!(client.symbol_get_by_name("shared").unwrap(), original);
        }
        let filter = format!("id='{}'", selected["id"].as_str().unwrap());
        let moved = command(
            program,
            &[
                "symbol",
                "set-namespace",
                "shared",
                "--namespace",
                "destination",
                "--where",
                &filter,
            ],
        );
        assert_eq!(moved["before"], *selected);
        assert_eq!(moved["after"]["id"], selected["id"]);
        assert_eq!(moved["after"]["name"], selected["name"]);
        assert_eq!(moved["after"]["namespace"], "destination");
        assert_eq!(
            move_symbol(client, &moved["after"], Some("destination"))["status"],
            "unchanged"
        );
        assert_eq!(reference_state(client), references);
        let error = client
            .send_command(
                "symbol_set_namespace",
                Some(json!({"name":"shared", "targets":[selected], "global":true})),
            )
            .unwrap_err();
        assert!(error.to_string().contains("Stale"), "{error:#}");
        // A second symbol at the same address must not merge with the moved one.
        let error = client
            .send_command(
                "symbol_set_namespace",
                Some(json!({"name":"shared", "targets":[unaffected], "namespace":"destination"})),
            )
            .unwrap_err();
        assert!(error.to_string().contains("already contains"), "{error:#}");
        assert_eq!(
            client.symbol_get_by_name("shared").unwrap()["symbols"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        let global = command(
            program,
            &[
                "symbol",
                "set-namespace",
                "shared",
                "--global",
                "--where",
                &filter,
            ],
        );
        assert_eq!(global["after"]["id"], selected["id"]);
        assert_eq!(global["after"]["namespace"], "Global");
        client.program_close().unwrap();
        client.open_program(program).unwrap();
        assert_eq!(reference_state(client), references);
        let reopened = client.symbol_get_by_name("shared").unwrap();
        assert!(reopened["symbols"]
            .as_array()
            .unwrap()
            .contains(&global["after"]));
        assert!(reopened["symbols"].as_array().unwrap().contains(unaffected));
    });
}

#[test]
#[serial]
fn primary_changes_only_persisted_local_labels_and_preserves_function_primary() {
    require_ghidra!();
    with_fixture(|client, program| {
        command(program, &["namespace", "create", "destination"]);
        let first = symbol(client, "first_label");
        let second = symbol(client, "second_label");
        assert_eq!(first["is_primary"], true);
        assert_eq!(second["is_primary"], false);
        let updated = command(
            program,
            &[
                "symbol",
                "set-primary",
                "second_label",
                "--address",
                "0x1030",
            ],
        );
        assert_eq!(updated["before"], second);
        assert_eq!(updated["after"]["is_primary"], true);
        assert_eq!(updated["previous_primary"], first);
        assert_eq!(symbol(client, "first_label")["is_primary"], false);
        assert_eq!(
            command(program, &["symbol", "set-primary", "second_label"])["status"],
            "unchanged"
        );
        let function = symbol(client, "method");
        let dynamic = client.symbol_get("0x1090").unwrap()["symbols"][0].clone();
        for target in [
            function.clone(),
            symbol(client, "function_alias"),
            dynamic.clone(),
            symbol(client, "outside_label"),
            symbol(client, "left"),
        ] {
            client
                .send_command(
                    "symbol_set_primary",
                    Some(json!({"name":target["name"], "targets":[target]})),
                )
                .unwrap_err();
        }
        let variables = client.symbol_get_by_name("value").unwrap();
        for target in [
            dynamic,
            symbol(client, "outside_label"),
            symbol(client, "left"),
            variables["symbols"][0].clone(),
        ] {
            client.send_command("symbol_set_namespace", Some(json!({"name":target["name"], "targets":[target], "namespace":"destination"}))).unwrap_err();
        }
        assert_eq!(symbol(client, "method"), function);
        client.program_close().unwrap();
        client.open_program(program).unwrap();
        assert_eq!(symbol(client, "second_label")["is_primary"], true);
        assert_eq!(symbol(client, "method"), function);
    });
}

#[test]
#[serial]
fn class_moves_report_native_thiscall_types_and_parameters_without_inferring_a_convention() {
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
        let method = symbol(client, "method");
        let moved = command(
            program,
            &[
                "symbol",
                "set-namespace",
                "method",
                "--namespace",
                "app::Widget",
                "--address",
                "0x1040",
            ],
        );
        assert_eq!(moved["after"]["id"], method["id"]);
        assert_eq!(moved["function_before"]["calling_convention"], "__thiscall");
        assert_eq!(moved["function_after"]["calling_convention"], "__thiscall");
        let before = moved["function_before"]["params"].as_array().unwrap();
        let after = moved["function_after"]["params"].as_array().unwrap();
        assert_eq!(before.len(), 2);
        assert_eq!(after.len(), 2);
        assert_eq!(before[0]["auto_parameter"], "THIS");
        assert_eq!(after[0]["auto_parameter"], "THIS");
        assert!(before[0]["type"].as_str().unwrap().contains("void"));
        assert!(after[0]["type"].as_str().unwrap().contains("Widget"));
        assert_eq!(before[0]["storage"], after[0]["storage"]);
        assert_eq!(before[1], after[1]);
        assert!(
            moved["created_types"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["path"] == "/app/Widget"),
            "{moved}"
        );
        let plain = move_symbol(client, &symbol(client, "plain"), Some("app::Widget"));
        assert_eq!(plain["function_before"], plain["function_after"]);
        assert_eq!(plain["function_after"]["calling_convention"], "__cdecl");
        assert_eq!(plain["created_types"], json!([]));
        client.program_close().unwrap();
        client.open_program(program).unwrap();
        let reopened = client
            .send_command(
                "get_function",
                Some(json!({"address":"0x1040", "with_signature":true})),
            )
            .unwrap();
        assert_eq!(
            reopened["signature_details"]["params"],
            moved["function_after"]["params"]
        );
        assert_eq!(symbol(client, "method"), moved["after"]);
        let global = move_symbol(client, &moved["after"], None);
        assert_eq!(global["function_after"]["calling_convention"], "__thiscall");
        assert_eq!(
            global["function_after"]["params"],
            moved["function_before"]["params"]
        );
        assert_eq!(global["created_types"], json!([]));
        assert!(client.type_get("/app/Widget").is_ok());
    });
}
