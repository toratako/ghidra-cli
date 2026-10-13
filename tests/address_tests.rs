//! Explicit address syntax and name resolution against an isolated raw program.

use ghidra_cli::ghidra::bridge::{import_oneshot, OneShotImportOptions};
use ghidra_cli::ipc::client::BridgeClient;
use serde_json::{json, Value};

#[macro_use]
mod common;

#[test]
fn explicit_addresses_and_exact_names_preserve_targets() {
    require_ghidra!();
    let directory = tempfile::Builder::new()
        .prefix("ghidra-address-")
        .tempdir()
        .unwrap();
    let project = directory.path().join("project");
    let binary = directory.path().join("addresses.bin");
    std::fs::write(&binary, vec![0xc3; 0x700]).unwrap();
    let installation = ghidra_cli::config::Config::load()
        .unwrap()
        .get_ghidra_installation()
        .unwrap();
    let program = import_oneshot(
        &project,
        &binary,
        &installation,
        &OneShotImportOptions {
            language: Some("x86:LE:32:default".into()),
            loader: Some("BinaryLoader".into()),
            loader_options: vec![("baseAddr".into(), "0x1000".into())],
            ..Default::default()
        },
    )
    .expect("import address fixture")
    .program;
    let harness = common::DaemonTestHarness::new(project.to_str().unwrap(), &program)
        .expect("start address fixture bridge");
    let client = harness.client().unwrap();
    client
        .script_run_source(
            include_str!("fixtures/address/CreateAddressFixture.java"),
            &[],
            &[],
            false,
        )
        .expect("create name and address collisions");

    check_name_and_address_reads(&client);
    check_symbol_address_names(&client);
    check_generated_name_collisions(&client, &program);
    client
        .script_run_source(
            include_str!("fixtures/readonly/CheckAddressLookupCancellation.java"),
            &[],
            &[],
            false,
        )
        .expect("name and external-thunk lookup cancellation and recovery");
    check_invalid_targets_do_not_mutate(&client, &harness);
    check_labels_do_not_select_functions(&client, &harness);
    check_address_only_ipc(&client);
    check_mutation_targets(&client, &harness);
    check_address_codec(&client);
    check_import_base_addresses(&client, &binary);
}

fn check_generated_name_collisions(client: &BridgeClient, program: &str) {
    let generated = client.symbol_get("0x1610").unwrap()["symbols"][0].clone();
    assert_eq!(generated["source"], "DEFAULT");
    let name = generated["name"].as_str().unwrap();
    let read = |target: &str| {
        client
            .send_command("read_memory", Some(json!({"address": target, "size": 1})))
            .unwrap()
    };
    // Generated labels remain candidates even when an indexed label has the
    // same name. Parameters and locals must retain that protection as well.
    assert_eq!(read(name), read("0x1610"));
    client.symbol_create_label("0x1611", name).unwrap();
    let variables: Vec<_> = client.symbol_list(None, None, None).unwrap()["symbols"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["namespace"] == "generated_owner")
        .cloned()
        .collect();
    assert_eq!(variables.len(), 2);
    for variable in &variables {
        let address = variable["address"].as_str().unwrap();
        assert!(client.symbol_get(address).unwrap()["symbols"]
            .as_array()
            .unwrap()
            .contains(variable));
        let name = variable["name"].as_str().unwrap();
        for target in [name.to_owned(), format!("generated_owner::{name}")] {
            assert_eq!(
                client
                    .send_command("memory_info", Some(json!({"address": target})))
                    .unwrap()["address"],
                address
            );
        }
    }
    let mut names = vec![name.to_owned()];
    for (index, variable) in variables.iter().enumerate() {
        let name = variable["name"].as_str().unwrap();
        client
            .symbol_create_label(&format!("0x{:x}", 0x1612 + index), name)
            .unwrap();
        names.push(name.to_owned());
    }
    let symbols_before = client.symbol_list(None, None, None).unwrap();
    let bytes_before = read("0x1610");
    let memory_before = client
        .send_command("read_memory", Some(json!({"address": "0x1611", "size": 3})))
        .unwrap();
    for name in names {
        let error = client
            .memory_write(&name, "90")
            .expect_err("generated and indexed symbols must make the target ambiguous");
        assert!(error.to_string().contains("Ambiguous"), "{error:#}");
        assert!(client
            .send_command("read_memory", Some(json!({"address": name, "size": 1})))
            .unwrap_err()
            .to_string()
            .contains("Ambiguous"));
    }
    // Qualification still selects the requested variable after a local label
    // makes its unqualified name ambiguous.
    for variable in &variables {
        let qualified = format!("generated_owner::{}", variable["name"].as_str().unwrap());
        assert_eq!(
            client
                .send_command("memory_info", Some(json!({"address": qualified})))
                .unwrap()["address"],
            variable["address"]
        );
    }
    assert_eq!(read("0x1610"), bytes_before);
    assert_eq!(
        client
            .send_command("read_memory", Some(json!({"address": "0x1611", "size": 3})))
            .unwrap(),
        memory_before
    );
    assert_eq!(
        client.symbol_list(None, None, None).unwrap(),
        symbols_before
    );
    client.program_close().unwrap();
    client.open_program(program).unwrap();
    assert_eq!(read("0x1610"), bytes_before);
    assert_eq!(
        client
            .send_command("read_memory", Some(json!({"address": "0x1611", "size": 3})))
            .unwrap(),
        memory_before
    );
    assert_eq!(
        client.symbol_list(None, None, None).unwrap(),
        symbols_before
    );
}

fn check_symbol_address_names(client: &BridgeClient) {
    for (name, address) in [
        ("handler<ns::Item>", "0x00001601"),
        ("scoped<ns::Item>", "0x00001602"),
        ("scope0::scoped<ns::Item>", "0x00001602"),
        ("scope0::0xentry", "0x00001607"),
        ("handler<ns::0xItem>", "0x00001608"),
        // Namespace symbols have NO_ADDRESS and cannot make a real label ambiguous.
        ("scope0", "0x00001605"),
    ] {
        let result = client
            .send_command("read_memory", Some(json!({"address":name, "size":1})))
            .unwrap_or_else(|error| panic!("resolve exact label {name}: {error:#}"));
        assert_eq!(result["address"], address);
    }
    for (target, address) in [
        ("scope0::collision", "0x1603"),
        ("scope0::0xcollision", "0x1609"),
    ] {
        let before = client
            .send_command("read_memory", Some(json!({"address":address, "size":2})))
            .unwrap();
        let error = client
            .send_command("memory_write", Some(json!({"address":target, "hex":"90"})))
            .expect_err("exact own-name and qualified-name collision must stay ambiguous");
        assert!(error.to_string().contains("Ambiguous"), "{error:#}");
        assert_eq!(
            client
                .send_command("read_memory", Some(json!({"address":address, "size":2})))
                .unwrap(),
            before
        );
    }
}

fn check_import_base_addresses(client: &BridgeClient, fixture: &std::path::Path) {
    let binary = fixture.with_file_name("base-address.bin");
    std::fs::write(&binary, [0xc3]).unwrap();
    let before = client.send_command("list_programs", None).unwrap();
    for (language, address) in [
        ("x86:LE:32:default", "0xffffffffffffffff"),
        ("x86:LE:32:default", "0x100000000"),
        ("x86:LE:32:default", "unknown:0x1000"),
        ("x86:LE:16:Real Mode", "0x100001000"),
    ] {
        let error = client
            .send_command(
                "import",
                Some(json!({
                    "binary_path": binary,
                    "program": "invalid-base-address",
                    "loader": "BinaryLoader",
                    "language": language,
                    "loader_options": [["baseAddr", address]],
                })),
            )
            .expect_err("out-of-range base address must fail before import");
        let detail = &error
            .downcast_ref::<ghidra_cli::ipc::protocol::BridgeCommandError>()
            .expect("structured invalid base address error")
            .detail;
        assert_eq!(detail["stage"], "import.options", "{error}");
        assert_eq!(detail["import_status"], "not_started", "{error}");
        assert_eq!(client.send_command("list_programs", None).unwrap(), before);
    }
}

fn get_function(client: &BridgeClient, target: &str) -> Value {
    client
        .send_command("get_function", Some(json!({"address": target})))
        .unwrap_or_else(|error| panic!("get function {target}: {error:#}"))
}

fn check_name_and_address_reads(client: &BridgeClient) {
    for (name, address, literal) in [
        ("add", "0x00001000", "literal_add"),
        ("dead", "0x00001100", "literal_dead"),
        ("12345", "0x00001200", "literal_digits"),
    ] {
        let function = get_function(client, name);
        assert_eq!(function["address"], address, "{name}");
        assert_eq!(function["name"], name);
        assert_eq!(get_function(client, address), function);
        assert_eq!(
            get_function(client, &address.replacen("0x", "0X", 1)),
            function
        );
        assert_eq!(get_function(client, &format!("0x{name}"))["name"], literal);
        assert_eq!(
            client.symbol_get(name).unwrap()["symbols"][0]["address"],
            address
        );
        assert_eq!(
            client
                .decompile(name.into(), false, false, false, false, None)
                .unwrap()["address"],
            address
        );
        assert_eq!(
            client.function_disasm(name, None).unwrap()["instructions"][0]["address"],
            address
        );
        assert_eq!(
            client.disasm(name, Some(1)).unwrap()["instructions"][0]["address"],
            address
        );
        for function_scope in [false, true] {
            assert_eq!(
                client.xrefs_from(name.to_owned(), function_scope).unwrap(),
                client
                    .xrefs_from(address.to_owned(), function_scope)
                    .unwrap(),
                "xref from name/address equivalence: {name}, function={function_scope}"
            );
        }
        for command in ["graph_callers", "graph_callees"] {
            let by_name = client
                .send_command(command, Some(json!({"function": name})))
                .unwrap();
            let by_address = client
                .send_command(command, Some(json!({"function": address})))
                .unwrap();
            assert_eq!(by_name["calls"], by_address["calls"], "{command}: {name}");
        }
    }
    let incoming = client.graph_callers("dead", None, None).unwrap();
    assert_eq!(incoming["calls"][0]["caller_address"], "0x00001000");
    assert_eq!(incoming["calls"][0]["callee_address"], "0x00001100");
    let outgoing = client.graph_callees("dead", None, None).unwrap();
    assert_eq!(outgoing["calls"][0]["callee_address"], "0x00001200");
    assert_eq!(
        get_function(client, "FUN_00001400")["address"],
        "0x00001400"
    );
    assert_eq!(
        client.function_disasm("FUN_00001400", None).unwrap()["instructions"][0]["address"],
        "0x00001400"
    );
    for (target, address) in [
        ("scope0::ambiguous", "0x00001300"),
        ("scope1::ambiguous", "0x00001310"),
    ] {
        assert_eq!(get_function(client, target)["address"], address);
        client
            .send_command(
                "function_set_noreturn",
                Some(json!({"target":target,"value":true})),
            )
            .unwrap();
        assert_eq!(get_function(client, target)["no_return"], true);
        client
            .send_command(
                "function_set_noreturn",
                Some(json!({"target":target,"value":false})),
            )
            .unwrap();
    }
}

fn target_requests(target: &str) -> Vec<(&'static str, Value)> {
    vec![
        ("get_function", json!({"address": target})),
        ("decompile", json!({"address": target})),
        ("disasm", json!({"address": target, "limit": 1})),
        ("function_disasm", json!({"target": target})),
        ("graph_callers", json!({"function": target})),
        ("graph_callees", json!({"function": target})),
        (
            "rename_function",
            json!({"old_name": target, "new_name": "wrong_target"}),
        ),
        (
            "function_set_signature",
            json!({"target": target, "signature": "int wrong_target(int value)"}),
        ),
        (
            "function_set_noreturn",
            json!({"target": target, "value": true}),
        ),
        ("delete_function", json!({"address": target})),
    ]
}

fn check_invalid_targets_do_not_mutate(client: &BridgeClient, harness: &common::DaemonTestHarness) {
    let before = client.list_functions(None, None, &[], false, None).unwrap();
    // These explicit-looking tokens really exist as labels, but malformed address
    // syntax must never fall back to any of those names.
    for target in [
        "0x",
        "0X",
        "0xnothex",
        "0x1000junk",
        "FUN_00001000",
        "1000",
        "ambiguous",
    ] {
        for (command, args) in target_requests(target) {
            let error = client.send_command(command, Some(args)).unwrap_err();
            if target == "ambiguous" {
                assert!(
                    error.to_string().contains("Ambiguous"),
                    "{command}: {error}"
                );
            }
        }
    }
    for target in ["0xnothex", "FUN_00001000", "ambiguous"] {
        common::ghidra(harness)
            .args(["function", "rename", target, "wrong_target"])
            .run()
            .assert_failure();
    }
    assert_eq!(
        client.list_functions(None, None, &[], false, None).unwrap(),
        before
    );
}

fn check_labels_do_not_select_functions(
    client: &BridgeClient,
    harness: &common::DaemonTestHarness,
) {
    let before = get_function(client, "add");
    for (label, address) in [
        ("entry_alias", "0x00001000"),
        ("interior_label", "0x00001005"),
    ] {
        assert_eq!(
            client.symbol_get(label).unwrap()["symbols"][0]["address"],
            address
        );
        assert_eq!(
            client.disasm(label, Some(1)).unwrap()["instructions"][0]["address"],
            address
        );
        common::ghidra(harness)
            .args(["function", "delete", label])
            .run()
            .assert_failure();
        assert!(client.function_disasm(label, None).is_err());
        assert_eq!(get_function(client, "add"), before);
    }
    // Explicit interior addresses still select the containing function.
    assert_eq!(get_function(client, "0x1005"), before);
    client
        .send_command(
            "function_set_noreturn",
            Some(json!({"target": "0x1005", "value": true})),
        )
        .unwrap();
    assert_eq!(get_function(client, "add")["no_return"], true);
    client
        .send_command(
            "function_set_noreturn",
            Some(json!({"target": "0x1005", "value": false})),
        )
        .unwrap();
    assert_eq!(get_function(client, "add"), before);
}

fn check_address_only_ipc(client: &BridgeClient) {
    client
        .comment_set("0X1600", "preserved comment", None)
        .unwrap();
    let comments = client.comment_get("0x1600").unwrap();
    let memory = client
        .send_command("read_memory", Some(json!({"address": "0x1600", "size": 8})))
        .unwrap();
    let symbols = client.symbol_list(None, None, None).unwrap();
    for address in ["1600", "ram:1600", "0xnothex"] {
        for (command, args) in [
            ("comment_get", json!({"address": address})),
            (
                "comment_set",
                json!({"address": address, "text": "wrong comment"}),
            ),
            ("comment_delete", json!({"address": address, "all": true})),
            (
                "define_data",
                json!({"address": address, "type_name": "int", "force": true}),
            ),
            (
                "symbol_create_label",
                json!({"address": address, "name": "wrong_symbol"}),
            ),
            ("read_memory", json!({"address": address, "size": 8})),
            (
                "memory_write",
                json!({"address": address, "hex": "00000000"}),
            ),
            ("define_code", json!({"target": address})),
            ("clear_range", json!({"start": address, "end": "0x1607"})),
        ] {
            assert!(
                client.send_command(command, Some(args)).is_err(),
                "{command} accepted {address}"
            );
        }
    }
    for (start, end) in [
        ("add", "0x1005"),
        ("0x1000", "dead"),
        ("0x1000", "register:0x1005"),
        ("0x1005", "0x1000"),
    ] {
        assert!(
            client
                .send_command("clear_range", Some(json!({"start": start, "end": end})))
                .is_err(),
            "clear endpoints must form a valid explicit range: {start}:{end}"
        );
    }
    let error = client
        .send_command(
            "rename_function",
            Some(json!({
                "old_name": "add", "new_name": "wrong_target", "address": "1000"
            })),
        )
        .unwrap_err();
    assert!(error.to_string().contains("address"), "{error}");
    assert_eq!(client.comment_get("0x1600").unwrap(), comments);
    assert_eq!(
        client
            .send_command("read_memory", Some(json!({"address": "0x1600", "size": 8})))
            .unwrap(),
        memory
    );
    assert_eq!(client.symbol_list(None, None, None).unwrap(), symbols);
    assert_eq!(
        client.function_disasm("add", None).unwrap()["instructions"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    // Failed define_data must also leave the listing undefined, not just retain bytes.
    client
        .script_run_source(
            include_str!("fixtures/address/VerifyAddressFailures.java"),
            &[],
            &[],
            false,
        )
        .unwrap();
}

fn check_mutation_targets(client: &BridgeClient, harness: &common::DaemonTestHarness) {
    for (name, address, literal_address) in [
        ("add", "0x00001000", "0xadd"),
        ("dead", "0x00001100", "0xdead"),
        ("12345", "0x00001200", "0x12345"),
    ] {
        let decoy = get_function(client, literal_address);
        let renamed = format!("renamed_{name}");
        common::ghidra(harness)
            .args(["function", "rename", name, &renamed])
            .run()
            .assert_success();
        assert_eq!(get_function(client, &renamed)["address"], address);
        assert_eq!(get_function(client, literal_address), decoy);
        client
            .send_command(
                "rename_function",
                Some(json!({"old_name": renamed, "new_name": name})),
            )
            .unwrap();
        let result = client
            .send_command(
                "function_set_signature",
                Some(json!({
                    "target": name, "signature": format!("int signature_{name}(int value)")
                })),
            )
            .unwrap();
        assert_eq!(result["address"], address);
        let signature = get_function(client, address)["signature"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(
            signature.contains("int") && signature.contains("value"),
            "{signature}"
        );
        assert_eq!(get_function(client, literal_address), decoy);
    }
}

fn check_address_codec(client: &BridgeClient) {
    // Compile the production codec beside this script, avoiding reflective access
    // to the bridge's private OSGi bundle and exercising real Ghidra address types.
    let codec = include_str!("../src/ghidra/scripts/ghidracli/query/AddressCodec.java")
        .replacen("package ghidracli.query;", "", 1)
        .replacen(
            "public final class AddressCodec",
            "final class AddressCodec",
            1,
        );
    let script = format!("{codec}\n{}", CODEC_CHECKS);
    client
        .script_run_source(&script, &[], &[], false)
        .expect("address codec invariants");
}

const CODEC_CHECKS: &str = include_str!("fixtures/address/CheckAddressCodec.java");
