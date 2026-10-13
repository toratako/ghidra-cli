//! Explicit bit-field edits preserve bit locations, neighboring components, and saved settings.

use super::common::helpers::GhidraResult;
use super::{create_type_edit_program, harness, type_command, TEST_PROGRAM};
use serde_json::{json, Value};
use serial_test::serial;

fn success(result: GhidraResult) -> Value {
    result.assert_success();
    result.data()
}

fn definition(program: &str, name: &str) -> Value {
    success(type_command(program, &["get", name]))
}

fn field<'a>(definition: &'a Value, name: &str) -> &'a Value {
    definition["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|field| field["name"] == name)
        .unwrap_or_else(|| panic!("Missing {name}: {definition}"))
}

fn create(
    program: &str,
    name: &str,
    offset: &str,
    storage: &str,
    bit_offset: &str,
    width: &str,
    attributes: &[&str],
) -> GhidraResult {
    let mut args = vec![
        "field",
        "create-bitfield",
        name,
        "--offset",
        offset,
        "--storage-size",
        storage,
        "--bit-offset",
        bit_offset,
        "--bit-size",
        width,
    ];
    args.extend_from_slice(attributes);
    type_command(program, &args)
}

fn set(program: &str, name: &str, field: &str, attributes: &[&str]) -> GhidraResult {
    let mut args = vec!["field", "set", name, "--field", field];
    args.extend_from_slice(attributes);
    type_command(program, &args)
}

fn without_ordinal(field: &Value) -> Value {
    let mut field = field.clone();
    field.as_object_mut().unwrap().remove("ordinal");
    field.as_object_mut().unwrap().remove("display_name");
    field
}

fn bit_value(field: &Value, bytes: &[u8], big: bool) -> u64 {
    let start = field["offset"].as_u64().unwrap() as usize;
    let size = field["size"].as_u64().unwrap() as usize;
    let mut value = 0u64;
    for index in 0..size {
        let byte = bytes[start + if big { index } else { size - index - 1 }];
        value = (value << 8) | u64::from(byte);
    }
    (value >> field["bit_offset"].as_u64().unwrap())
        & ((1 << field["bit_size"].as_u64().unwrap()) - 1)
}

fn fixture(program: &str) {
    let client = harness().client().unwrap();
    client.open_program(program).unwrap();
    client
        .script_run_source(
            include_str!("../fixtures/types/CreateBitEditFixtures.java"),
            &[],
            &[],
            false,
        )
        .unwrap();
}

#[test]
#[serial]
fn bitfield_growth_checks_parent_and_applied_data_before_saving() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    let client = harness().client().unwrap();
    client.open_program(&program).unwrap();
    client
        .script_run_source(
            include_str!("../fixtures/types/CreateBitfieldGrowthCases.java"),
            &[],
            &[],
            false,
        )
        .unwrap();
    let parent = definition(&program, "BitsParent");
    for name in ["EmbeddedBits", "EdgeBits"] {
        let before = definition(&program, name);
        let failed = create(
            &program,
            name,
            "4",
            "4",
            "0",
            "3",
            &["--name", "flags", "--type", "uint32_t"],
        );
        failed
            .assert_failure()
            .assert_stderr_contains("Unsafe resize");
        let error: Value = serde_json::from_str(&failed.stderr).unwrap();
        assert_eq!(error["detail"]["rolled_back"], true, "{error}");
        client.program_close().unwrap();
        assert_eq!(definition(&program, name), before);
        assert_eq!(definition(&program, "BitsParent"), parent);
    }
    client
        .script_run_source(
            include_str!("../fixtures/types/CheckBitfieldGrowthRollback.java"),
            &[],
            &[],
            false,
        )
        .unwrap();
    let grown = success(create(
        &program,
        "FreeBits",
        "4",
        "4",
        "0",
        "3",
        &["--name", "flags", "--type", "uint32_t"],
    ));
    assert_eq!(grown["size_after"], 8);
    client.program_close().unwrap();
    assert_eq!(definition(&program, "FreeBits")["size"], 8);
    client.open_program(TEST_PROGRAM).unwrap();
}

#[test]
#[serial]
fn bitfield_growth_preserves_existing_applied_settings_when_inserting_before_fields() {
    require_ghidra!();
    let client = harness().client().unwrap();
    for (language, bit_offset) in [("x86:LE:32:default", "0"), ("PowerPC:BE:32:default", "61")] {
        let program = create_type_edit_program(language);
        client.open_program(&program).unwrap();
        client
            .script_run_source(
                include_str!("../fixtures/types/CreateBitfieldInsertionSettings.java"),
                &[],
                &[],
                false,
            )
            .unwrap();
        let before = without_ordinal(field(&definition(&program, "GrowingBits"), "tail"));
        let created = success(create(
            &program,
            "GrowingBits",
            "0",
            "8",
            bit_offset,
            "3",
            &["--name", "flags", "--type", "uint32_t"],
        ));
        assert_eq!(created["after"]["offset"], 0);
        assert_eq!(created["size_after"], 8);
        assert_eq!(
            without_ordinal(field(&definition(&program, "GrowingBits"), "tail")),
            before
        );
        let guarded = definition(&program, "GuardedBits");
        let rejected = create(
            &program,
            "GuardedBits",
            "0",
            "8",
            bit_offset,
            "3",
            &["--name", "flags", "--type", "uint32_t"],
        );
        rejected
            .assert_failure()
            .assert_stderr_contains("applied component settings changed");
        let error: Value = serde_json::from_str(&rejected.stderr).unwrap();
        assert_eq!(error["detail"]["rolled_back"], true, "{error}");
        client.program_close().unwrap();
        assert_eq!(definition(&program, "GuardedBits"), guarded);
        client.open_program(&program).unwrap();
        client
            .script_run_source(
                include_str!("../fixtures/types/CheckBitfieldInsertionSettings.java"),
                &[],
                &[],
                false,
            )
            .unwrap();
        client.open_program(TEST_PROGRAM).unwrap();
    }
}

#[test]
#[serial]
fn explicit_bitfields_keep_program_endian_locations_across_edits_and_reopen() {
    require_ghidra!();
    let client = harness().client().unwrap();
    for (language, big) in [
        ("x86:LE:32:default", false),
        ("PowerPC:BE:32:default", true),
    ] {
        let program = create_type_edit_program(language);
        fixture(&program);
        let low = success(create(
            &program,
            "Bits",
            "0",
            "4",
            "0",
            "3",
            &["--type", "Word", "--name", "low", "--comment", "low bits"],
        ));
        assert_eq!(low["status"], "created");
        assert_eq!(low["after"]["offset"], if big { 3 } else { 0 });
        assert_eq!(low["after"]["size"], 1);
        success(create(
            &program,
            "Bits",
            "0",
            "4",
            "3",
            "10",
            &["--type", "uint32_t", "--name", "cross"],
        ));
        let unnamed = success(create(
            &program,
            "Bits",
            "0",
            "4",
            "13",
            "3",
            &["--type", "FlagsEnum", "--comment", "anonymous"],
        ));
        let before = definition(&program, "Bits");
        let ordinal = unnamed["after"]["ordinal"].as_u64().unwrap().to_string();
        let annotated = success(type_command(
            &program,
            &[
                "field",
                "set",
                "Bits",
                "--ordinal",
                &ordinal,
                "--comment",
                "recovered",
            ],
        ));
        assert_eq!(annotated["after"]["name"], Value::Null);
        assert_eq!(annotated["after"]["comment"], "recovered");
        assert_eq!(annotated["after"]["base_type"], "FlagsEnum");
        let same_byte = success(set(&program, "Bits", "cross", &["--comment", "cross byte"]));
        assert_eq!(same_byte["after"]["name"], "cross");
        assert_eq!(
            field(&definition(&program, "Bits"), "low"),
            field(&before, "low")
        );
        client
            .script_run_source(
                include_str!("../fixtures/types/SetBitEditSettings.java"),
                &[],
                &[],
                false,
            )
            .unwrap();
        let before_base_edit = definition(&program, "Bits");
        set(&program, "Bits", "cross", &["--type", "uint8_t"])
            .assert_failure()
            .assert_stderr_contains("clipping");
        assert_eq!(definition(&program, "Bits"), before_base_edit);
        let changed_base = success(set(&program, "Bits", "cross", &["--type", "uint16_t"]));
        assert_eq!(changed_base["after"]["bit_size"], 10);
        assert_eq!(changed_base["after"]["size"], 2);
        let bytes = if big {
            [0xde, 0xad, 0xb6, 0xd5]
        } else {
            [0xd5, 0xb6, 0xad, 0xde]
        };
        assert_eq!(bit_value(&changed_base["after"], &bytes, big), 730);
        let narrower = success(set(&program, "Bits", "cross", &["--bit-size", "5"]));
        assert_eq!(narrower["after"]["size"], 1);
        assert_eq!(narrower["after"]["offset"], if big { 3 } else { 0 });
        assert_eq!(bit_value(&narrower["after"], &bytes, big), 730 & 31);
        let saved = definition(&program, "Bits");
        set(&program, "Bits", "cross", &["--bit-size", "6"])
            .assert_failure()
            .assert_stderr_contains("storage byte range");
        assert_eq!(definition(&program, "Bits"), saved);
        client.program_close().unwrap();
        assert_eq!(definition(&program, "Bits"), saved);
        client
            .script_run_source(
                include_str!("../fixtures/types/CheckBitEditSettings.java"),
                &[],
                &[],
                false,
            )
            .unwrap();
        let cleared = success(type_command(
            &program,
            &["field", "clear", "Bits", "--field", "low"],
        ));
        assert_eq!(cleared["size_before"], 12);
        assert_eq!(cleared["size_after"], 12);
        let after_clear = definition(&program, "Bits");
        assert_eq!(
            without_ordinal(field(&after_clear, "cross")),
            without_ordinal(field(&saved, "cross"))
        );
        assert_eq!(
            without_ordinal(field(&after_clear, "tail")),
            without_ordinal(field(&saved, "tail"))
        );
        let anonymous = after_clear["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|field| field["comment"] == "recovered")
            .unwrap();
        assert_eq!(
            without_ordinal(anonymous),
            without_ordinal(&annotated["after"])
        );
        let ordinal = anonymous["ordinal"].as_u64().unwrap().to_string();
        success(type_command(
            &program,
            &["field", "clear", "Bits", "--ordinal", &ordinal],
        ));
        let deleted = success(type_command(
            &program,
            &["field", "delete", "Bits", "--field", "cross"],
        ));
        assert_eq!(
            deleted["size_after"], 12,
            "nonpacked bit deletion retains byte storage"
        );
        assert_eq!(field(&definition(&program, "Bits"), "tail")["offset"], 8);
        let final_state = definition(&program, "Bits");
        client.program_close().unwrap();
        assert_eq!(definition(&program, "Bits"), final_state);
    }
    client.open_program(TEST_PROGRAM).unwrap();
}

#[test]
#[serial]
fn bitfield_collisions_clipping_and_invalid_wire_edits_roll_back() {
    require_ghidra!();
    let client = harness().client().unwrap();
    for language in ["x86:LE:32:default", "PowerPC:BE:32:default"] {
        let program = create_type_edit_program(language);
        fixture(&program);
        success(create(
            &program,
            "Bits",
            "0",
            "4",
            "0",
            "3",
            &["--type", "uint32_t", "--name", "low"],
        ));
        success(create(
            &program,
            "Bits",
            "0",
            "4",
            "4",
            "3",
            &["--type", "uint32_t", "--name", "next"],
        ));
        let before = definition(&program, "Bits");
        for (result, message) in [
            (
                create(
                    &program,
                    "Bits",
                    "0",
                    "4",
                    "2",
                    "3",
                    &["--type", "uint32_t"],
                ),
                "overlaps",
            ),
            (
                create(
                    &program,
                    "Bits",
                    "8",
                    "4",
                    "0",
                    "1",
                    &["--type", "uint32_t"],
                ),
                "overlaps",
            ),
            (
                create(&program, "Bits", "4", "2", "0", "9", &["--type", "uint8_t"]),
                "clipping",
            ),
            (
                create(&program, "Bits", "4", "2", "0", "3", &["--type", "float"]),
                "Unsupported base",
            ),
            (
                set(&program, "Bits", "low", &["--bit-size", "5"]),
                "overlaps",
            ),
            (
                set(&program, "Bits", "low", &["--bit-size", "9"]),
                "storage byte range",
            ),
            (
                set(
                    &program,
                    "Bits",
                    "low",
                    &["--type", "uint16_t", "--size", "2"],
                ),
                "--size is not supported",
            ),
            (
                set(&program, "Bits", "tail", &["--bit-size", "3"]),
                "existing bit-field",
            ),
        ] {
            result.assert_failure().assert_stderr_contains(message);
            let error: Value = serde_json::from_str(&result.stderr).unwrap();
            assert_eq!(error["detail"]["rolled_back"], true, "{error}");
            assert_eq!(definition(&program, "Bits"), before);
        }
        for (command, args, message) in [
            (
                "type_field_set",
                json!({"type_name":"Bits", "field":"low", "bit_size":0}),
                "must be positive",
            ),
            (
                "type_field_create_bitfield",
                json!({"type_name":"Bits", "offset":4, "storage_size":2,
                "bit_offset":0, "bit_size":0, "field_type":"uint8_t"}),
                "must be positive",
            ),
            (
                "type_field_set",
                json!({"type_name":"Bits", "field":"low", "bit_size":1.5}),
                "bit_size must be an integer",
            ),
            (
                "type_field_set",
                json!({"type_name":"Bits", "ordinal":0.5, "comment":"wrong"}),
                "ordinal must be an integer",
            ),
            (
                "type_field_create_bitfield",
                json!({"type_name":"Bits", "offset":4, "storage_size":-1,
                "bit_offset":0, "bit_size":3, "field_type":"uint32_t"}),
                "storage_size must be an integer",
            ),
        ] {
            let error = client.send_command(command, Some(args)).unwrap_err();
            assert!(error.to_string().contains(message), "{error:#}");
            assert_eq!(definition(&program, "Bits"), before);
        }
        client.program_close().unwrap();
        assert_eq!(definition(&program, "Bits"), before);
        let wider = success(set(&program, "Bits", "low", &["--bit-size", "4"]));
        assert_eq!(wider["after"]["bit_size"], 4);
        assert_eq!(wider["size_after"], 12);
        success(create(
            &program,
            "Bits",
            "4",
            "4",
            "7",
            "9",
            &["--type", "uint32_t", "--name", "far"],
        ));
        let neighbor = success(create(
            &program,
            "Bits",
            "4",
            "4",
            "0",
            "3",
            &["--type", "uint32_t", "--name", "neighbor"],
        ));
        let cleared = success(type_command(
            &program,
            &["field", "clear", "Bits", "--field", "far"],
        ));
        assert_eq!(cleared["before"]["size"], 2);
        assert_eq!(cleared["size_after"], 12);
        assert_eq!(
            without_ordinal(field(&definition(&program, "Bits"), "neighbor")),
            without_ordinal(&neighbor["after"])
        );
        let current = definition(&program, "Bits");
        let tail_ordinal = field(&current, "tail")["ordinal"]
            .as_u64()
            .unwrap()
            .to_string();
        let ordinary = success(type_command(
            &program,
            &[
                "field",
                "set",
                "Bits",
                "--ordinal",
                &tail_ordinal,
                "--comment",
                "ordinary ordinal",
            ],
        ));
        assert_eq!(ordinary["after"]["name"], "tail");
        assert_eq!(ordinary["after"]["offset"], 8);
    }
    client.open_program(TEST_PROGRAM).unwrap();
}

#[test]
#[serial]
fn packed_and_zero_width_bitfields_allow_metadata_and_native_deletion() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:32:default");
    let client = harness().client().unwrap();
    client.open_program(&program).unwrap();
    client
        .script_run_source(
            include_str!("../fixtures/types/CreatePackedBitEditFixture.java"),
            &[],
            &[],
            false,
        )
        .unwrap();
    let before = definition(&program, "PackedBits");
    success(set(
        &program,
        "PackedBits",
        "first",
        &["--name", "renamed", "--comment", "metadata"],
    ));
    let zero = success(type_command(
        &program,
        &[
            "field",
            "set",
            "PackedBits",
            "--ordinal",
            "1",
            "--comment",
            "aligned",
        ],
    ));
    assert_eq!(zero["after"]["bit_size"], 0);
    assert_eq!(zero["after"]["name"], Value::Null);
    let after = definition(&program, "PackedBits");
    assert_eq!(after["size"], before["size"]);
    assert_eq!(after["packing_enabled"], true);
    assert_eq!(field(&after, "last"), field(&before, "last"));
    for result in [
        set(&program, "PackedBits", "renamed", &["--bit-size", "4"]),
        set(&program, "PackedBits", "renamed", &["--type", "uint16_t"]),
        create(
            &program,
            "PackedBits",
            "0",
            "4",
            "8",
            "3",
            &["--type", "uint32_t"],
        ),
        type_command(
            &program,
            &["field", "clear", "PackedBits", "--field", "renamed"],
        ),
    ] {
        result
            .assert_failure()
            .assert_stderr_contains("packing disabled");
        assert_eq!(definition(&program, "PackedBits"), after);
    }
    client.program_close().unwrap();
    assert_eq!(definition(&program, "PackedBits"), after);
    client
        .script_run_source(
            include_str!("../fixtures/types/CheckPackedBitEditSettings.java"),
            &[],
            &[],
            false,
        )
        .unwrap();
    let deleted = success(type_command(
        &program,
        &["field", "delete", "PackedBits", "--ordinal", "1"],
    ));
    assert_eq!(deleted["before"]["bit_size"], 0);
    let remaining = definition(&program, "PackedBits");
    assert_eq!(remaining["components"].as_array().unwrap().len(), 2);
    client.program_close().unwrap();
    assert_eq!(definition(&program, "PackedBits"), remaining);
    client.open_program(TEST_PROGRAM).unwrap();
}

#[test]
#[serial]
fn bitfield_edits_preserve_explicit_settings_without_materializing_inherited_defaults() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:32:default");
    let client = harness().client().unwrap();
    client.open_program(&program).unwrap();
    client
        .script_run_source(
            include_str!("../fixtures/types/CreateInheritedBitSettings.java"),
            &[],
            &[],
            false,
        )
        .unwrap();
    success(set(
        &program,
        "InheritedBits",
        "inherited",
        &["--bit-size", "2"],
    ));
    success(set(
        &program,
        "InheritedBits",
        "explicit",
        &["--bit-size", "2"],
    ));
    client.program_close().unwrap();
    definition(&program, "InheritedBits");
    client
        .script_run_source(
            include_str!("../fixtures/types/ChangeInheritedBitDefault.java"),
            &[],
            &[],
            false,
        )
        .unwrap();
    success(set(
        &program,
        "InheritedBits",
        "inherited",
        &["--type", "OtherWord"],
    ));
    client.program_close().unwrap();
    definition(&program, "InheritedBits");
    client
        .script_run_source(
            include_str!("../fixtures/types/CheckNewBitBaseDefaults.java"),
            &[],
            &[],
            false,
        )
        .unwrap();
    client.open_program(TEST_PROGRAM).unwrap();
}

#[test]
#[serial]
fn bitfield_insertion_rejects_existing_offsets_that_overflow_native_bit_ordering() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:32:default");
    let client = harness().client().unwrap();
    client.open_program(&program).unwrap();
    client
        .script_run_source(
            include_str!("../fixtures/types/CreateLargeBitOffsetFixture.java"),
            &[],
            &[],
            false,
        )
        .unwrap();
    let result = create(
        &program,
        "HugeBits",
        "0",
        "1",
        "0",
        "3",
        &["--type", "uint32_t"],
    );
    result
        .assert_failure()
        .assert_stderr_contains("Existing field exceeds Ghidra's supported bit-offset range");
    let error: Value = serde_json::from_str(&result.stderr).unwrap();
    assert_eq!(error["detail"]["rolled_back"], true);
    client.program_close().unwrap();
    client.open_program(&program).unwrap();
    // Query defined components directly: enumerating hundreds of millions of padding rows is unnecessary.
    client
        .script_run_source(
            include_str!("../fixtures/types/CheckLargeBitOffsetFixture.java"),
            &[],
            &[],
            false,
        )
        .unwrap();
    client.open_program(TEST_PROGRAM).unwrap();
}

#[test]
#[serial]
fn existing_zero_width_bitfields_at_the_structure_end_can_be_cleared() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:32:default");
    let client = harness().client().unwrap();
    client.open_program(&program).unwrap();
    client
        .script_run_source(
            include_str!("../fixtures/types/CreateEndZeroBitFixtures.java"),
            &[],
            &[],
            false,
        )
        .unwrap();
    for (name, expected_size) in [("EmptyZeroBits", 0), ("EndZeroBits", 4)] {
        let before = definition(&program, name);
        assert_eq!(before["size"], expected_size);
        let boundary = before["components"].as_array().unwrap().last().unwrap();
        assert_eq!(boundary["bit_size"], 0);
        assert_eq!(boundary["offset"], expected_size);
        let ordinal = boundary["ordinal"].as_u64().unwrap().to_string();
        let cleared = success(type_command(
            &program,
            &["field", "clear", name, "--ordinal", &ordinal],
        ));
        assert_eq!(cleared["before"], *boundary);
        assert_eq!(cleared["size_after"], expected_size);
        let after = definition(&program, name);
        assert_eq!(
            after["components"].as_array().unwrap().len(),
            if expected_size == 0 { 0 } else { 1 }
        );
        if expected_size != 0 {
            assert_eq!(field(&after, "word"), field(&before, "word"));
        }
        client.program_close().unwrap();
        assert_eq!(definition(&program, name), after);
    }
    client.open_program(TEST_PROGRAM).unwrap();
}

#[test]
#[serial]
fn shared_byte_insertion_rejects_native_component_count_overflow() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:32:default");
    let client = harness().client().unwrap();
    client.open_program(&program).unwrap();
    client
        .script_run_source(
            include_str!("../fixtures/types/CreateMaximumBitComponentFixture.java"),
            &[],
            &[],
            false,
        )
        .unwrap();
    let error = client
        .send_command(
            "type_field_create_bitfield",
            Some(json!({
                "type_name":"MaximumBits", "offset":0, "storage_size":1, "bit_offset":4,
                "bit_size":3, "field_type":"uint32_t", "field_name":"second"
            })),
        )
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("component count exceeds its supported range"),
        "{error:#}"
    );
    client.program_close().unwrap();
    client.open_program(&program).unwrap();
    client
        .script_run_source(
            include_str!("../fixtures/types/CheckMaximumBitComponentFixture.java"),
            &[],
            &[],
            false,
        )
        .unwrap();
    client.open_program(TEST_PROGRAM).unwrap();
}

#[test]
#[serial]
fn removing_a_wide_bitfield_rejects_padding_component_count_overflow() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:32:default");
    let client = harness().client().unwrap();
    client.open_program(&program).unwrap();
    client
        .script_run_source(
            include_str!("../fixtures/types/CreateBitRemovalCountFixture.java"),
            &[],
            &[],
            false,
        )
        .unwrap();
    for command in ["type_field_clear", "type_field_delete"] {
        let error = client
            .send_command(
                command,
                Some(json!({
                    "type_name":"RemovalCountBits", "field":"wide"
                })),
            )
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("component count exceeds its supported range"),
            "{error:#}"
        );
        client.program_close().unwrap();
        client.open_program(&program).unwrap();
        client
            .script_run_source(
                include_str!("../fixtures/types/CheckBitRemovalCountFixture.java"),
                &[],
                &[],
                false,
            )
            .unwrap();
    }
    client.open_program(TEST_PROGRAM).unwrap();
}
