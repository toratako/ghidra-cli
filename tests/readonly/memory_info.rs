use super::{harness, TEST_PROGRAM};
use crate::common::{ghidra, test_project};
use serde_json::{json, Value};
use serial_test::serial;

#[test]
#[serial]
fn memory_info_classifies_listing_and_preserves_object_and_address_space_boundaries() {
    require_ghidra!();
    let harness = harness();
    let client = harness.client().unwrap();
    let name = format!("memory-info-{}", uuid::Uuid::new_v4());
    client
        .script_run_source(
            include_str!("CreateMemoryInfoFixture.java"),
            std::slice::from_ref(&name),
            &[],
            false,
        )
        .unwrap();
    client.open_program(&name).unwrap();
    let checked = std::panic::catch_unwind(|| {
        let info = |target: &str| -> Value {
            client
                .send_command("memory_info", Some(json!({"address": target})))
                .unwrap()
        };
        let entry = info("info_function");
        assert_eq!(entry, info("0x1000"));
        assert_eq!(entry["address"], "0x00001000");
        assert_eq!(entry["kind"], "instruction");
        assert_eq!(
            entry["instruction"],
            json!({
                "address": "0x00001000", "end": "0x00001004", "size": 5,
                "offset": 0, "mnemonic": "MOV"
            })
        );
        assert_eq!(
            entry["function"],
            json!({"name": "info_function", "address": "0x00001000"})
        );
        assert_eq!(
            entry["memory"],
            json!({
                "name": "code", "permissions": "rx", "start": "0x00001000",
                "end": "0x000011ff", "initialized": true
            })
        );
        assert!(entry["data"].is_null());
        let interior = info("0x1004");
        let mut expected = entry.clone();
        expected["address"] = json!("0x00001004");
        expected["instruction"]["offset"] = json!(4);
        assert_eq!(interior, expected);

        // A function body can also contain undefined bytes and defined data.
        let gap = info("0x1005");
        assert_eq!(gap["kind"], "undefined");
        assert!(gap["instruction"].is_null());
        assert!(gap["data"].is_null());
        assert_eq!(gap["function"], entry["function"]);
        let scalar = info("0x1017");
        assert_eq!(scalar["kind"], "data");
        assert_eq!(scalar["function"], entry["function"]);
        assert!(scalar["instruction"].is_null());
        assert_eq!(
            scalar["data"],
            json!({
                "address": "0x00001010", "end": "0x00001017", "size": 8,
                "offset": 7, "type": "qword", "type_path": "/qword"
            })
        );

        // Interior structure/array addresses retain the top-level applied object.
        let record = info("info_record");
        assert_eq!(
            record,
            info("1000"),
            "numeric-looking names are exact symbols"
        );
        assert_eq!(record["kind"], "data");
        assert_eq!(
            record["data"],
            json!({
                "address": "0x00002000", "end": "0x0000200b", "size": 12,
                "offset": 0, "type": "InfoRecord", "type_path": "/memory_info/InfoRecord"
            })
        );
        assert!(record["function"].is_null());
        assert_eq!(record["memory"]["permissions"], "rw");
        let mut expected = record.clone();
        expected["address"] = json!("0x00002007");
        expected["data"]["offset"] = json!(7);
        assert_eq!(info("0x2007"), expected);
        assert_eq!(info("0x200c")["kind"], "undefined");

        let uninitialized = info("0x3000");
        assert_eq!(uninitialized["kind"], "undefined");
        assert_eq!(uninitialized["memory"]["name"], "bss");
        assert_eq!(uninitialized["memory"]["initialized"], false);
        let uninitialized_data = info("0x3012");
        assert_eq!(uninitialized_data["kind"], "data");
        assert_eq!(uninitialized_data["memory"]["initialized"], false);
        assert_eq!(uninitialized_data["data"]["address"], "0x00003010");
        assert_eq!(uninitialized_data["data"]["offset"], 2);

        let unmapped = info("0x9000");
        assert_eq!(
            unmapped,
            json!({
                "address": "0x00009000", "kind": "unmapped", "instruction": null,
                "data": null, "function": null, "memory": null
            })
        );
        let overlay = info("info_overlay:0x1002");
        assert_eq!(overlay["kind"], "data");
        assert_eq!(overlay["address"], "info_overlay:0x00001002");
        assert_eq!(overlay["data"]["address"], "info_overlay:0x00001000");
        assert_eq!(overlay["data"]["end"], "info_overlay:0x00001003");
        assert_eq!(overlay["data"]["offset"], 2);
        assert_eq!(overlay["memory"]["start"], "info_overlay:0x00001000");
        assert_eq!(overlay["memory"]["end"], "info_overlay:0x0000100f");
        assert!(overlay["function"].is_null());
        assert_eq!(info("info_overlay_data"), info("info_overlay:0x1000"));
        let overlay_unmapped = info("info_overlay:0x1100");
        assert_eq!(overlay_unmapped["address"], "info_overlay:0x00001100");
        assert_eq!(overlay_unmapped["kind"], "unmapped");
        assert!(overlay_unmapped["memory"].is_null());
        assert_eq!(info("0x1100")["kind"], "undefined");

        let output = ghidra(harness)
            .args(["memory", "info", "0x2007", "--json"])
            .with_project(test_project(), &name)
            .run();
        output.assert_success();
        assert_eq!(output.json::<Value>(), json!([expected]));
    });
    client.open_program(TEST_PROGRAM).unwrap();
    client.program_delete(&name).unwrap();
    if let Err(panic) = checked {
        std::panic::resume_unwind(panic);
    }
}
