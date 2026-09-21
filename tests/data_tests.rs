//! Applied-type data values, bounded expansion, and interior/overlapping components.

use ghidra_cli::ghidra::bridge::{import_oneshot, OneShotImportOptions};
use ghidra_cli::ipc::client::BridgeClient;
use serde_json::{json, Value};
use serial_test::serial;

#[macro_use]
mod common;

fn read(client: &BridgeClient, target: &str, depth: u32, elements: u32) -> Value {
    client
        .send_command(
            "data_read",
            Some(json!({"target": target, "max_depth": depth, "max_elements": elements})),
        )
        .expect("read applied data")
}

fn field<'a>(data: &'a Value, name: &str) -> &'a Value {
    data["components"]
        .as_array()
        .expect("components")
        .iter()
        .find(|component| component["name"] == name)
        .unwrap_or_else(|| panic!("missing field {name} in {data}"))
}

fn expanded_count(data: &Value) -> usize {
    data["components"]
        .as_array()
        .map(|children| children.iter().map(|child| 1 + expanded_count(child)).sum())
        .unwrap_or_default()
}

#[test]
#[serial]
fn applied_data_values_and_bounded_traversal() {
    require_ghidra!();
    let directory = tempfile::Builder::new()
        .prefix("ghidra-data-")
        .tempdir()
        .expect("fixture directory");
    let project = directory.path().join("project");
    let binary = directory.path().join("data.bin");
    std::fs::write(&binary, vec![0u8; 8192]).expect("write data fixture");
    let installation = ghidra_cli::config::Config::load()
        .expect("load configuration")
        .get_ghidra_install_dir()
        .expect("Ghidra installation");
    let program = import_oneshot(
        &project,
        &binary,
        &installation,
        &OneShotImportOptions {
            language: Some("x86:LE:64:default".to_owned()),
            loader: Some("BinaryLoader".to_owned()),
            loader_options: vec![("baseAddr".to_owned(), "0x1000".to_owned())],
            ..Default::default()
        },
    )
    .expect("import raw data fixture");
    let harness = common::DaemonTestHarness::new(project.to_str().unwrap(), &program)
        .expect("start data fixture bridge");
    let client = harness.client().unwrap();
    client
        .script_run_source(
            include_str!("fixtures/data/CreateDataFixture.java"),
            &[],
            &[],
            false,
        )
        .expect("apply fixture data");

    let root = read(&client, "data_record", 4, 100);
    assert_eq!(root["kind"], "structure");
    assert_eq!(root["size"], 36);
    assert_eq!(root["truncated"], false);
    assert_eq!(root["parents"], json!([]));
    assert_eq!(root["target_offset"], 0);
    let inner = field(&root, "inner");
    assert_eq!(field(inner, "large")["value"], u64::MAX.to_string());
    assert_eq!(field(inner, "large")["signed"], false);
    assert_eq!(field(inner, "large")["type"], "ExactUnsigned");
    assert_eq!(field(inner, "negative")["value"], "-7");
    assert_eq!(field(inner, "negative")["signed"], true);
    let values = field(&root, "values");
    assert_eq!(values["kind"], "array");
    assert_eq!(values["components"][0]["value"], "4660");
    assert_eq!(values["components"][1]["value"], "0");
    assert_eq!(values["components"][2]["value"], "65535");
    let pointer = field(&root, "next");
    assert_eq!(pointer["kind"], "pointer");
    assert_eq!(pointer["reference"]["symbol"], "data_record");
    assert_eq!(pointer["reference"]["mapped"], true);
    assert!(
        pointer.get("components").is_none(),
        "pointers must not be followed"
    );
    assert_eq!(field(&root, "text")["value"], "hello");
    let union = field(&root, "interpretations");
    assert_eq!(union["overlapping"], true);
    assert_eq!(field(union, "number")["value"], "305419896");
    assert_eq!(field(union, "bytes")["components"][0]["value"], "120");
    assert_eq!(
        field(union, "number")["address"],
        field(union, "bytes")["address"]
    );

    let shallow = read(&client, "data_record", 1, 100);
    assert_eq!(shallow["truncated"], true);
    assert_eq!(
        field(&shallow, "inner")["truncation_reasons"],
        json!(["max_depth"])
    );
    let bounded = read(&client, "data_record", 4, 4);
    assert_eq!(bounded["truncated"], true);
    assert_eq!(bounded["expanded_elements"], 4);
    assert_eq!(
        expanded_count(&bounded),
        4,
        "budget must span all nested arrays/structs"
    );
    assert_eq!(read(&client, "data_record", 0, 0)["components"], json!([]));

    // An interior target reaches a distant array element without expanding its predecessors.
    let interior = read(&client, "0x1621", 2, 1);
    assert_eq!(interior["value"], "4242");
    assert_eq!(interior["target_offset"], 1);
    assert_eq!(interior["component_path"], json!([400]));
    assert_eq!(interior["parents"][0]["name"], "data_large_array");
    assert_eq!(interior["parents"][0]["kind"], "array");
    let array_start = read(&client, "0x100c", 1, 3);
    assert_eq!(array_start["kind"], "array");
    assert_eq!(array_start["parents"][0]["name"], "data_record");
    let union_interior = read(&client, "0x1021", 3, 100);
    assert_eq!(union_interior["kind"], "union");
    assert_eq!(union_interior["target_offset"], 1);
    assert_eq!(union_interior["components"].as_array().unwrap().len(), 2);

    let bits = read(&client, "0x1200", 1, 100);
    assert_eq!(field(&bits, "low")["value"], "5");
    assert_eq!(field(&bits, "low")["bit_length"], 3);
    assert_eq!(field(&bits, "high")["value"], "17");
    assert_eq!(field(&bits, "high")["bit_offset"], 3);
    assert_eq!(read(&client, "0x1110", 0, 0)["value"], i64::MIN.to_string());
    assert_eq!(read(&client, "0x1190", 0, 0)["value"], "255");
    let odd_unsigned = read(&client, "0x1198", 0, 0);
    assert_eq!(odd_unsigned["value"], 0xffabcd_u32.to_string());
    assert_eq!(odd_unsigned["bit_length"], 24);
    assert_eq!(odd_unsigned["signed"], false);
    assert_eq!(odd_unsigned["representation"], "WIDE");
    let odd_signed = read(&client, "0x11b0", 0, 0);
    assert_eq!(odd_signed["value"], "-7");
    assert_eq!(odd_signed["signed"], true);
    assert_eq!(odd_signed["representation"], "NEGATIVE");
    assert_eq!(read(&client, "0x1194", 0, 0)["value"], "4660");
    assert_eq!(read(&client, "0x1180", 0, 0)["value"], "-1.25");
    let null_pointer = read(&client, "0x11a0", 0, 0);
    assert_eq!(null_pointer["state"], "available");
    assert!(null_pointer["value"].as_str().unwrap().ends_with('0'));
    let zero = read(&client, "data_zero", 0, 0);
    assert_eq!(zero["state"], "available");
    assert_eq!(zero["value"], "0");
    let uninitialized = read(&client, "data_uninitialized", 0, 0);
    assert_eq!(uninitialized["state"], "unavailable");
    assert_eq!(uninitialized["reason"], "uninitialized_memory");
    assert!(uninitialized["value"].is_null());
    let partial = read(&client, "0x5000", 1, 100);
    assert_eq!(field(&partial, "partial")["state"], "unavailable");
    assert_eq!(field(&partial, "partial")["reason"], "unreadable_memory");
    assert_eq!(field(&partial, "available")["state"], "available");
    assert_eq!(field(&partial, "available")["value"], "0");
    assert_eq!(
        read(&client, "0x1800", 0, 0)["value"],
        u128::MAX.to_string()
    );
    let long_string = read(&client, "0x10000", 4, 100);
    assert_eq!(long_string["truncated"], true);
    assert_eq!(long_string["reason"], "value_size_limit");
    assert!(long_string["value"].is_null());

    let list = common::ghidra(&harness)
        .args([
            "data",
            "list",
            "--filter",
            "name^data_",
            "--sort",
            "name",
            "--limit",
            "2",
            "--offset",
            "1",
        ])
        .json_format()
        .run();
    list.assert_success();
    let list: Value = list.json();
    assert_eq!(list.as_array().unwrap().len(), 2);
    assert_eq!(list[0]["name"], "data_record");
    assert_eq!(list[1]["name"], "data_uninitialized");
    let output = common::ghidra(&harness)
        .args(["data", "read", "data_zero", "--fields", "value,state"])
        .json_format()
        .run();
    output.assert_success();
    let output: Value = output.json();
    assert_eq!(output, json!([{"value":"0", "state":"available"}]));

    // Values come from current analysis memory; no reapplication of the type is needed.
    client
        .send_command(
            "memory_write",
            Some(json!({"address":"data_zero", "hex":"2a00000000000000"})),
        )
        .expect("patch typed data");
    assert_eq!(read(&client, "data_zero", 0, 0)["value"], "42");
    assert!(client
        .send_command("data_read", Some(json!({"target":"0x2fff"})))
        .is_err());
    assert!(client
        .send_command(
            "data_read",
            Some(json!({"target":"data_zero", "max_depth":-1}))
        )
        .is_err());
    assert!(client
        .send_command(
            "data_read",
            Some(json!({"target":"data_zero", "max_elements":100001}))
        )
        .is_err());
}
