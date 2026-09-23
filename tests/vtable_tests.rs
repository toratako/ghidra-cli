//! ABI table decoding with native Ghidra pointers and compiler-produced C++ layouts.

use ghidra_cli::ghidra::bridge::{import_oneshot, OneShotImportOptions};
use ghidra_cli::ipc::client::BridgeClient;
use serde_json::{json, Value};
use serial_test::serial;

#[macro_use]
mod common;

#[test]
#[serial]
fn vtables_32_bit_itanium_and_msvc() {
    check_raw_layout("x86:LE:32:default", 4, false);
}

#[test]
#[serial]
fn vtables_64_bit_itanium_msvc_and_relative() {
    check_raw_layout("x86:LE:64:default", 8, false);
}

#[test]
#[serial]
fn vtables_big_endian_aarch64() {
    check_raw_layout("AARCH64:BE:64:v8A", 8, true);
}

#[test]
#[serial]
fn vtables_arm_thumb_preserve_encoded_pointer_and_normalized_function() {
    check_raw_layout("ARM:LE:32:v8", 4, false);
}

fn check_raw_layout(language: &str, pointer_size: usize, big_endian: bool) {
    require_ghidra!();
    let directory = tempfile::Builder::new()
        .prefix("ghidra-vtable-")
        .tempdir()
        .unwrap();
    let project = directory.path().join("project");
    let binary = directory.path().join("vtable.bin");
    std::fs::write(&binary, vec![0u8; 0x300]).unwrap();
    let installation = ghidra_cli::config::Config::load()
        .unwrap()
        .get_ghidra_install_dir()
        .unwrap();
    let program = import_oneshot(
        &project,
        &binary,
        &installation,
        &OneShotImportOptions {
            language: Some(language.to_owned()),
            loader: Some("BinaryLoader".to_owned()),
            loader_options: vec![("baseAddr".to_owned(), "0x1000".to_owned())],
            ..Default::default()
        },
    )
    .expect("import raw vtable fixture");
    let harness = common::DaemonTestHarness::new(project.to_str().unwrap(), &program).unwrap();
    let client = harness.client().unwrap();
    client
        .script_run_source(
            include_str!("fixtures/vtable/CreateVtableFixture.java"),
            &[],
            &[],
            false,
        )
        .expect("create vtable layout and explicit targets");

    let output = common::ghidra(&harness)
        .args([
            "memory",
            "read-vtable",
            "absolute_address_point",
            "--entries",
            "5",
            "--abi",
            "itanium",
        ])
        .json_format()
        .run();
    output.assert_success();
    let absolute: Value = output.data();
    assert_eq!(address(&absolute["address"]), 0x1020);
    assert_eq!(absolute["abi"], "itanium");
    assert_eq!(absolute["encoding"], "absolute");
    assert_eq!(absolute["pointer_size"], pointer_size);
    assert_eq!(absolute["entry_size"], pointer_size);
    assert_eq!(
        absolute["endian"],
        if big_endian { "big" } else { "little" }
    );
    assert_complete(&absolute, 5);
    assert_eq!(absolute["header"]["complete"], true);
    assert_eq!(absolute["header"]["offset_to_top"]["signed_value"], -16);
    assert_eq!(
        address(&absolute["header"]["rtti"]["target_address"]),
        0x1200
    );

    let thumb = language.starts_with("ARM:");
    let mode_bit = u64::from(thumb);
    let targets = [0x2000 + mode_bit, 0, 0x2040, 0x9000, 0x2020 + mode_bit];
    for (index, target) in targets.into_iter().enumerate() {
        let row = &absolute["entries"][index];
        assert_eq!(row["index"], index);
        assert_eq!(row["offset"], index * pointer_size);
        assert_eq!(
            address(&row["address"]),
            0x1020 + (index * pointer_size) as u64
        );
        assert_eq!(row["readable"], true);
        assert_eq!(row["is_null"], target == 0);
        assert_eq!(address(&row["target_address"]), target);
        assert_eq!(row["mapped"], !matches!(index, 1 | 3));
    }
    let rows = &absolute["entries"];
    assert_eq!(rows[0]["function"], "virtual_target");
    assert_eq!(address(&rows[0]["function_address"]), 0x2000);
    assert_eq!(address(&rows[0]["code_address"]), 0x2000);
    assert_eq!(rows[2]["symbol"], "undefined_target");
    assert!(rows[2]["function"].is_null(), "{}", rows[2]);
    assert!(rows[3]["function"].is_null(), "{}", rows[3]);
    assert_eq!(rows[4]["function"], "virtual_thunk");
    assert_eq!(address(&rows[4]["function_address"]), 0x2020);
    assert_thunk_target(&rows[4]["thunk_target"], 0x2000);
    assert_thunk_target(&rows[4]["thunk_final_target"], 0x2000);

    let no_rtti = read(&client, "0x10a0", 1, "itanium", "absolute");
    assert_complete(&no_rtti, 1);
    assert_eq!(no_rtti["header"]["offset_to_top"]["signed_value"], 0);
    assert_eq!(no_rtti["header"]["rtti"]["is_null"], true);
    assert_eq!(no_rtti["entries"][0]["function"], "virtual_target");

    // A missing header cannot discard readable slots; a missing slot cannot
    // shorten the requested index space or masquerade as a null pointer.
    let missing_header = read(&client, "0x2000", 1, "itanium", "absolute");
    assert_complete(&missing_header, 1);
    assert_eq!(missing_header["header"]["complete"], false);
    let partial = read(&client, "0x12f0", 5, "itanium", "absolute");
    assert_eq!(partial["complete"], false);
    assert_eq!(partial["requested_entries"], 5);
    assert_eq!(partial["read_entries"], 16 / pointer_size);
    let partial_rows = partial["entries"].as_array().unwrap();
    assert_eq!(partial_rows.len(), 5);
    for row in &partial_rows[16 / pointer_size..] {
        assert_eq!(row["readable"], false);
        assert!(row["value"].is_null(), "{row}");
        assert!(row["is_null"].is_null(), "{row}");
    }

    if language.starts_with("x86:") {
        let msvc = read(&client, "0x1120", 2, "msvc", "absolute");
        assert_complete(&msvc, 2);
        assert_eq!(msvc["header"]["complete"], true);
        assert_eq!(
            address(&msvc["header"]["complete_object_locator"]["target_address"]),
            0x1240
        );
        let locator = &msvc["header"]["locator"];
        assert_eq!(locator["readable"], true);
        assert_eq!(locator["signature"], u64::from(pointer_size == 8));
        assert_eq!(locator["offset"], 16);
        assert_eq!(locator["cd_offset"], 4);
        assert_eq!(
            address(&locator["type_descriptor"]["target_address"]),
            0x1200
        );
        assert_eq!(
            address(&locator["class_descriptor"]["target_address"]),
            0x1220
        );
        if pointer_size == 8 {
            assert_eq!(address(&locator["self"]["target_address"]), 0x1240);
            assert_eq!(locator["self_matches"], true);
        }
        assert_eq!(msvc["entries"][0]["function"], "virtual_target");
        assert_eq!(msvc["entries"][1]["function"], "virtual_thunk");
    }

    if pointer_size == 8 {
        let relative = read(&client, "0x11a0", 4, "itanium", "relative32");
        assert_complete(&relative, 4);
        assert_eq!(relative["entry_size"], 4);
        assert_eq!(relative["header"]["offset_to_top"]["signed_value"], -24);
        assert_eq!(
            address(&relative["header"]["rtti_reference"]["target_address"]),
            0x1260
        );
        assert_eq!(
            address(&relative["header"]["rtti"]["target_address"]),
            0x1200
        );
        for (index, target) in [0x800, 0x2000, 0, 0x9000].into_iter().enumerate() {
            let row = &relative["entries"][index];
            assert_eq!(address(&row["relative_base"]), 0x11a0);
            if target == 0 {
                assert!(row["target_address"].is_null(), "{row}");
            } else {
                assert_eq!(address(&row["target_address"]), target);
            }
        }
        assert_eq!(relative["entries"][0]["displacement"], -0x9a0);
        assert_eq!(relative["entries"][0]["function"], "negative_target");
        assert_eq!(relative["entries"][1]["function"], "virtual_target");
        assert_eq!(relative["entries"][2]["is_null"], true);
    }

    if language == "x86:LE:64:default" {
        for (target, expected_signature) in [("0x1140", 99), ("0x1160", 1)] {
            let malformed = read(&client, target, 1, "msvc", "absolute");
            assert_complete(&malformed, 1);
            assert_eq!(malformed["entries"][0]["function"], "virtual_target");
            assert_eq!(malformed["header"]["complete"], false);
            let locator = &malformed["header"]["locator"];
            assert_eq!(locator["readable"], true);
            assert_eq!(locator["signature"], expected_signature);
            assert!(locator["error"].is_string(), "{malformed}");
            if expected_signature == 1 {
                assert_eq!(locator["self_matches"], false);
            }
        }
        let no_locator = read(&client, "0x10a0", 1, "msvc", "absolute");
        assert_complete(&no_locator, 1);
        assert!(no_locator["header"]["locator"].is_null());
        let overflow = read(&client, "0x11c0", 1, "itanium", "relative32");
        assert_complete(&overflow, 1);
        let row = &overflow["entries"][0];
        assert_eq!(row["displacement"], i32::MIN);
        assert_eq!(row["is_null"], false);
        assert!(row["target_address"].is_null(), "{overflow}");
        assert!(row["error"].is_string(), "{overflow}");
        for args in [
            json!({"target":"0x1020","entries":0,"abi":"itanium"}),
            json!({"target":"0x1020","entries":65537,"abi":"itanium"}),
            json!({"target":"0x1020","entries":1,"abi":"msvc","encoding":"relative32"}),
        ] {
            client
                .send_command("vtable_read", Some(args.clone()))
                .expect_err(&format!("invalid vtable request accepted: {args}"));
        }
        client
            .script_run_source(
                include_str!("fixtures/vtable/CheckVtableReadOnly.java"),
                &[],
                &[],
                false,
            )
            .expect("read-only and cancellation vtable probe");
    }

    client.program_close().unwrap();
    client.open_program(&program).unwrap();
    assert_eq!(read(&client, "0x1020", 5, "itanium", "absolute"), absolute);
}

#[test]
#[serial]
fn compiled_cpp_itanium_primary_and_secondary_address_points() {
    check_compiled_layout(
        include_str!("fixtures/vtable/layout.elf.hex"),
        "absolute",
        8,
    );
}

#[test]
#[serial]
fn compiled_cpp_relative_itanium_primary_and_secondary_address_points() {
    check_compiled_layout(
        include_str!("fixtures/vtable/relative.elf.hex"),
        "relative32",
        4,
    );
}

fn check_compiled_layout(hex: &str, encoding: &str, entry_size: usize) {
    with_compiled_layout(hex, "layout.o", &entry_size.to_string(), |client| {
        let primary = read(client, "derived_primary", 2, "itanium", encoding);
        let secondary = read(client, "derived_secondary", 1, "itanium", encoding);
        assert_complete(&primary, 2);
        assert_complete(&secondary, 1);
        assert_eq!(primary["header"]["complete"], true);
        assert_eq!(secondary["header"]["complete"], true);
        assert_eq!(primary["header"]["offset_to_top"]["signed_value"], 0);
        assert_eq!(secondary["header"]["offset_to_top"]["signed_value"], -8);
        assert_eq!(primary["header"]["rtti"]["symbol"], "_ZTI7Derived");
        assert_eq!(
            primary["header"]["rtti"]["target_address"],
            secondary["header"]["rtti"]["target_address"]
        );
        assert_eq!(primary["entries"][0]["function"], "_ZN7Derived4leftEv");
        assert_eq!(primary["entries"][1]["function"], "_ZN7Derived5rightEv");
        assert_eq!(
            secondary["entries"][0]["function"],
            "_ZThn8_N7Derived5rightEv"
        );
    });
}

#[test]
#[serial]
fn compiled_cpp_msvc_x64_primary_and_secondary_locators() {
    with_compiled_layout(
        include_str!("fixtures/vtable/msvc.coff.hex"),
        "layout.obj",
        "msvc",
        |client| {
            let primary = read(client, "derived_primary", 1, "msvc", "absolute");
            let secondary = read(client, "derived_secondary", 1, "msvc", "absolute");
            for table in [&primary, &secondary] {
                assert_complete(table, 1);
                assert_eq!(table["header"]["complete"], true, "{table}");
                let locator = &table["header"]["locator"];
                assert_eq!(locator["signature"], 1);
                assert_eq!(locator["cd_offset"], 0);
                assert_eq!(locator["self_matches"], true);
                assert_eq!(locator["self"]["target_address"], locator["address"]);
                assert_eq!(locator["type_descriptor"]["symbol"], "??_R0?AUDerived@@@8");
                assert_eq!(locator["class_descriptor"]["symbol"], "??_R3Derived@@8");
            }
            assert_eq!(primary["header"]["locator"]["offset"], 0);
            assert_eq!(secondary["header"]["locator"]["offset"], 8);
            assert_eq!(primary["entries"][0]["function"], "?left@Derived@@UEAAHXZ");
            assert_eq!(
                secondary["entries"][0]["function"],
                "?right@Derived@@UEAAHXZ"
            );
        },
    );
}

fn with_compiled_layout(
    hex: &str,
    filename: &str,
    prepare_arg: &str,
    check: impl FnOnce(&BridgeClient),
) {
    require_ghidra!();
    let directory = tempfile::Builder::new()
        .prefix("ghidra-compiled-vtable-")
        .tempdir()
        .unwrap();
    let binary = directory.path().join(filename);
    let project = directory.path().join("project");
    let hex: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
        .collect();
    std::fs::write(&binary, bytes).unwrap();
    let installation = ghidra_cli::config::Config::load()
        .unwrap()
        .get_ghidra_install_dir()
        .unwrap();
    let program = import_oneshot(
        &project,
        &binary,
        &installation,
        &OneShotImportOptions::default(),
    )
    .expect("import compiler-produced C++ object");
    let harness = common::DaemonTestHarness::new(project.to_str().unwrap(), &program).unwrap();
    let client = harness.client().unwrap();
    client
        .script_run_source(
            include_str!("fixtures/vtable/PrepareCompiledVtable.java"),
            &[prepare_arg.to_owned()],
            &[],
            false,
        )
        .expect("label actual compiler-emitted address points");
    check(&client);
}

fn read(client: &BridgeClient, target: &str, entries: usize, abi: &str, encoding: &str) -> Value {
    client
        .send_command(
            "vtable_read",
            Some(json!({"target":target,"entries":entries,"abi":abi,"encoding":encoding})),
        )
        .expect("read explicit vtable")
}

fn address(value: &Value) -> u64 {
    u64::from_str_radix(
        value
            .as_str()
            .expect("address string")
            .strip_prefix("0x")
            .expect("hex prefix"),
        16,
    )
    .expect("unsigned address")
}

fn assert_complete(value: &Value, count: usize) {
    assert_eq!(value["requested_entries"], count, "{value}");
    assert_eq!(value["read_entries"], count, "{value}");
    assert_eq!(value["complete"], true, "{value}");
    assert_eq!(value["entries"].as_array().unwrap().len(), count, "{value}");
}

fn assert_thunk_target(value: &Value, target: u64) {
    assert_eq!(address(&value["address"]), target);
}
