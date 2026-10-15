use super::*;
use std::collections::HashSet;

#[test]
#[serial]
fn type_import_file_and_stdin_create_saved_definitions() {
    require_ghidra!();
    let harness = harness();
    let temp = tempfile::tempdir().unwrap();
    let category = format!("/Input{}", unique_suffix());
    for mode in ["file", "stdin"] {
        let name = format!("From_{mode}");
        let code = format!("struct {name} {{ int value; }};\n");
        let mut command = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli");
        command.current_dir(temp.path()).args([
            "type",
            "import-c",
            "--project",
            test_project(),
            "--program",
            TEST_PROGRAM,
            "--category",
            &category,
        ]);
        if mode == "file" {
            std::fs::write(temp.path().join("recovered types.h"), &code).unwrap();
            command.args(["--file", "recovered types.h"]);
        } else {
            command.arg("--stdin").write_stdin(code);
        }
        command.assert().success();
        let result = ghidra(harness)
            .args(["type", "get", &format!("{category}/{name}"), "--json"])
            .with_project(test_project(), TEST_PROGRAM)
            .run();
        result.assert_success();
        let value: serde_json::Value = result.data();
        assert_eq!(value["components"][0]["name"], "value");
    }
    harness.client().unwrap().program_close().unwrap();
    let result = ghidra(harness)
        .args(["type", "get", &format!("{category}/From_file"), "--json"])
        .with_project(test_project(), TEST_PROGRAM)
        .run();
    result.assert_success();
}

#[test]
#[serial]
fn import_into_functions_category_reports_declared_structure() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    let result = type_command(
        &program,
        &[
            "import-c",
            "--category",
            "/functions",
            "--code",
            "struct Reported { int value; };",
        ],
    );
    result.assert_success();
    let receipt: serde_json::Value = result.data();
    assert!(
        receipt["types"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["name"] == "Reported" && row["path"] == "/functions/Reported"),
        "{receipt}"
    );
    assert_eq!(
        type_command(&program, &["get", "/functions/Reported"]).data::<serde_json::Value>()["kind"],
        "struct"
    );
    harness()
        .client()
        .unwrap()
        .open_program(TEST_PROGRAM)
        .unwrap();
}

#[test]
#[serial]
fn type_import_parse_failure_restores_types_and_applied_data_after_reopen() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    type_command(
        &program,
        &[
            "import-c",
            "--code",
            "struct Existing { int value; int tail; };",
        ],
    )
    .assert_success();
    let client = harness().client().unwrap();
    client
        .script_run_source(
            include_str!("../fixtures/types/ApplyImportRollbackFixture.java"),
            &[],
            &[],
            false,
        )
        .unwrap();
    let before = type_command(&program, &["list", "--limit", "0"]);
    before.assert_success();
    let before: serde_json::Value = before.data();

    // Both syntax and lexical failures follow valid replacement declarations.
    // They must leave the live definitions and their uses untouched. The
    // unterminated comment throws TokenMgrError rather than an Exception.
    for invalid_suffix in ["struct Broken { int value[; };", "/* unterminated comment"] {
        let code = format!(
            "struct Existing {{ long long changed; }}; struct Fresh {{ int marker; }}; {invalid_suffix}"
        );
        let failed = type_command(&program, &["import-c", "--code", &code]);
        failed
            .assert_failure()
            .assert_stderr_contains("C parse error");
        let error: serde_json::Value = serde_json::from_str(&failed.stderr).unwrap();
        assert_eq!(error["detail"]["rolled_back"], true, "{error}");
        assert!(error["detail"].get("partial_changes_saved").is_none());

        for reopen in [false, true] {
            if reopen {
                client.program_close().unwrap();
                client.open_program(&program).unwrap();
            }
            let after = type_command(&program, &["list", "--limit", "0"]);
            after.assert_success();
            assert_eq!(after.data::<serde_json::Value>(), before);
            client
                .script_run_source(
                    include_str!("../fixtures/types/CheckImportRollbackFixture.java"),
                    &[],
                    &[],
                    false,
                )
                .unwrap();
        }
    }
    client.open_program(TEST_PROGRAM).unwrap();
}

#[test]
#[serial]
fn type_import_rejects_unevaluated_and_narrowed_array_lengths_atomically() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    let client = harness().client().unwrap();
    common::with_temporary_program(&client, &program, TEST_PROGRAM, || {
        type_command(
            &program,
            &["import-c", "--code", "struct Existing { int original; };"],
        )
        .assert_success();
        let before = type_command(&program, &["get", "/Existing"]).data::<serde_json::Value>();
        let types = type_command(&program, &["list", "--limit", "0"]).data::<serde_json::Value>();
        for declaration in [
            "struct MissingLength { int values[UNKNOWN]; };",
            "typedef int MissingLength[UNKNOWN + 1];",
            "typedef int MissingLength[4294967296];",
            "struct MissingLength { int values[1ULL << 32]; };",
        ] {
            let code = format!("struct Existing {{ char changed; }}; {declaration}");
            let rejected = type_command(&program, &["import-c", "--code", &code]);
            rejected.assert_failure();
            let error: serde_json::Value = serde_json::from_str(&rejected.stderr).unwrap();
            assert_eq!(error["detail"]["rolled_back"], true, "{error}");
            for reopen in [false, true] {
                if reopen {
                    client.program_close().unwrap();
                    client.open_program(&program).unwrap();
                }
                assert_eq!(
                    type_command(&program, &["get", "/Existing"]).data::<serde_json::Value>(),
                    before
                );
                assert_eq!(
                    type_command(&program, &["list", "--limit", "0"]).data::<serde_json::Value>(),
                    types
                );
            }
        }
        type_command(
            &program,
            &["import-c", "--code", "struct [[gnu::packed]] Calculated { int values[(2 + 1) * 2]; char bytes[sizeof(struct Existing)]; char inline_enum[sizeof(enum { INLINE = 3 })]; int tail[]; }; int ignored(int *values, int index) { return values[index]; }"],
        )
        .assert_success();
        let calculated =
            type_command(&program, &["get", "/Calculated"]).data::<serde_json::Value>();
        assert_eq!(calculated["size"], 32);
        let imported =
            type_command(&program, &["list", "--limit", "0"]).data::<serde_json::Value>();
        assert_eq!(
            imported
                .as_array()
                .unwrap()
                .iter()
                .filter(|ty| ty["kind"] == "enum")
                .count(),
            1,
            "{imported}"
        );
        client.program_close().unwrap();
        client.open_program(&program).unwrap();
        assert_eq!(
            type_command(&program, &["get", "/Calculated"]).data::<serde_json::Value>(),
            calculated
        );
    });
}

#[test]
#[serial]
fn type_import_rejects_discarded_enum_members_and_base_structures() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    type_command(
        &program,
        &["import-c", "--code", "struct Existing { int original; };"],
    )
    .assert_success();
    let before = type_command(&program, &["get", "/Existing"]).data::<serde_json::Value>();
    let listed = type_command(&program, &["list", "--limit", "0"]).data::<serde_json::Value>();
    let client = harness().client().unwrap();
    for declaration in [
        "struct Dropped : MissingBase { int value; };",
        "enum Dropped { FIRST = 1, FIRST = 2, LAST = 3 };",
    ] {
        let code = format!("struct Existing {{ char changed; }}; {declaration}");
        let failed = type_command(&program, &["import-c", "--code", &code]);
        failed
            .assert_failure()
            .assert_stderr_contains("C parser discarded");
        let error: serde_json::Value = serde_json::from_str(&failed.stderr).unwrap();
        assert_eq!(error["detail"]["rolled_back"], true, "{error}");
        for reopen in [false, true] {
            if reopen {
                client.program_close().unwrap();
                client.open_program(&program).unwrap();
            }
            assert_eq!(
                type_command(&program, &["get", "/Existing"]).data::<serde_json::Value>(),
                before
            );
            assert_eq!(
                type_command(&program, &["list", "--limit", "0"]).data::<serde_json::Value>(),
                listed
            );
        }
    }
    type_command(
        &program,
        &["import-c", "--code", "enum Aliases { FIRST = 1, SAME = 1, LAST = 3 }; struct Derived : Existing { char value; };"],
    )
    .assert_success();
    let aliases = type_command(&program, &["get", "/Aliases"]).data::<serde_json::Value>();
    assert_eq!(aliases["members"].as_array().unwrap().len(), 3);
    let derived = type_command(&program, &["get", "/Derived"]).data::<serde_json::Value>();
    assert_eq!(derived["size"], 8);
    assert_eq!(derived["components"][0]["type_path"], "/Existing");
    client.program_close().unwrap();
    assert_eq!(
        type_command(&program, &["get", "/Derived"]).data::<serde_json::Value>(),
        derived
    );
    client.open_program(TEST_PROGRAM).unwrap();
}

#[test]
#[serial]
fn type_import_rejects_truncated_existing_applications_without_saving_changes() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    type_command(
        &program,
        &[
            "import-c",
            "--code",
            "struct Imported { int value; }; struct Embedded { int value; };",
        ],
    )
    .assert_success();
    let client = harness().client().unwrap();
    client
        .script_run_source(
            include_str!("../fixtures/types/CreateConstrainedImportApplication.java"),
            &[],
            &[],
            false,
        )
        .unwrap();
    let paths = ["/Imported", "/Embedded", "/ConstrainedHolder"];
    let before: Vec<serde_json::Value> = paths
        .iter()
        .map(|path| type_command(&program, &["get", path]).data())
        .collect();
    for name in ["Imported", "Embedded"] {
        let code = format!("struct Fresh {{ int marker; }}; struct {name} {{ long long value; }};");
        let failed = type_command(&program, &["import-c", "--code", &code]);
        failed
            .assert_failure()
            .assert_stderr_contains("Unsafe resize");
        let error: serde_json::Value = serde_json::from_str(&failed.stderr).unwrap();
        assert_eq!(error["detail"]["rolled_back"], true, "{error}");
        client.program_close().unwrap();
        client.open_program(&program).unwrap();
        for (path, expected) in paths.iter().zip(&before) {
            assert_eq!(
                &type_command(&program, &["get", path]).data::<serde_json::Value>(),
                expected
            );
        }
        type_command(&program, &["get", "Fresh"]).assert_failure();
        client
            .script_run_source(
                include_str!("../fixtures/types/CheckConstrainedImportApplication.java"),
                &[],
                &[],
                false,
            )
            .unwrap();
    }
    client.open_program(TEST_PROGRAM).unwrap();
}

#[test]
#[serial]
fn type_import_propagates_multiple_replacements_through_existing_parents() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    type_command(
        &program,
        &[
            "import-c",
            "--code",
            "struct First { int value; }; struct Second { int value; }; \
         struct Holder { struct First first; struct Second second; }; \
         struct Wrapper { struct Holder holder; char tail; }; \
         struct Morph { int value; }; struct MorphHolder { struct Morph item; };",
        ],
    )
    .assert_success();
    let client = harness().client().unwrap();
    client
        .script_run_source(
            include_str!("../fixtures/types/ApplyMultiReplacement.java"),
            &[],
            &[],
            false,
        )
        .unwrap();
    type_command(
        &program,
        &[
            "import-c",
            "--code",
            "struct First { long long value; }; struct Second { long long value; }; \
         struct Holder { struct First left; struct Second right; }; union Morph { int value; };",
        ],
    )
    .assert_success();
    client.program_close().unwrap();
    client.open_program(&program).unwrap();
    client
        .script_run_source(
            include_str!("../fixtures/types/CheckMultiReplacement.java"),
            &[],
            &[],
            false,
        )
        .unwrap();
    client.open_program(TEST_PROGRAM).unwrap();
}

#[test]
#[serial]
fn type_import_rejects_lossy_floating_specifiers_without_changing_definitions() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    type_command(
        &program,
        &["import-c", "--code", "struct Existing { int value; };"],
    )
    .assert_success();
    let before: serde_json::Value = type_command(&program, &["list", "--limit", "0"]).data();
    for declaration in [
        "struct Existing { long double value; };",
        "typedef long /* comment */ float Lossy;",
        "typedef long signed double Lossy;",
        "typedef long signed float Lossy;",
        "typedef long unsigned double Lossy;",
    ] {
        let code = format!("struct Fresh {{ int value; }}; {declaration}");
        type_command(&program, &["import-c", "--code", &code])
            .assert_failure()
            .assert_stderr_contains("Unsupported C floating-point specifiers");
        harness().client().unwrap().program_close().unwrap();
        assert_eq!(
            type_command(&program, &["list", "--limit", "0"]).data::<serde_json::Value>(),
            before
        );
    }
    type_command(
        &program,
        &[
            "import-c",
            "--code",
            "struct Precise { longdouble value; double ordinary; long long integer; signed long signed_integer; long unsigned unsigned_integer; };",
        ],
    )
    .assert_success();
    let precise: serde_json::Value = type_command(&program, &["get", "Precise"]).data();
    assert_eq!(precise["components"][0]["type"], "longdouble");
    assert_eq!(precise["components"][1]["type"], "double");
    assert_eq!(precise["components"][2]["type"], "longlong");
    assert_eq!(precise["components"][3]["type"], "long");
    assert_eq!(precise["components"][4]["type"], "ulong");
    harness().client().unwrap().program_close().unwrap();
    assert_eq!(
        type_command(&program, &["get", "Precise"]).data::<serde_json::Value>(),
        precise
    );
    harness()
        .client()
        .unwrap()
        .open_program(TEST_PROGRAM)
        .unwrap();
}

#[test]
#[serial]
fn type_import_rejects_overflowing_new_composite_layouts_before_saving() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:32:default");
    let client = harness().client().unwrap();
    super::common::with_temporary_program(&client, &program, TEST_PROGRAM, || {
        let before = type_command(&program, &["list", "--limit", "0"]);
        before.assert_success();
        let before: serde_json::Value = before.data();
        for code in [
            "struct OverflowingImport { char bytes[2147483647]; char extra; };",
            "struct PointerToOverflow { struct { char bytes[2147483647]; char extra; } *value; };",
            "typedef char OverflowingArray[2147483647][2];",
        ] {
            let rejected = type_command(&program, &["import-c", "--code", code]);
            rejected
                .assert_failure()
                .assert_stderr_contains("supported range");
            let error: serde_json::Value = serde_json::from_str(&rejected.stderr).unwrap();
            assert_eq!(error["detail"]["rolled_back"], true, "{error}");
            let after = type_command(&program, &["list", "--limit", "0"]);
            after.assert_success();
            assert_eq!(after.data::<serde_json::Value>(), before);
            client.program_close().unwrap();
            let saved = type_command(&program, &["list", "--limit", "0"]);
            saved.assert_success();
            assert_eq!(saved.data::<serde_json::Value>(), before);
        }
        type_command(
            &program,
            &[
                "import-c",
                "--code",
                "struct MaximumImport { char bytes[2147483646]; char extra; };",
            ],
        )
        .assert_success();
        let maximum = type_command(&program, &["get", "/MaximumImport"]);
        maximum.assert_success();
        let maximum: serde_json::Value = maximum.data();
        assert_eq!(maximum["size"], i32::MAX);
        client.program_close().unwrap();
        let saved = type_command(&program, &["get", "/MaximumImport"]);
        saved.assert_success();
        assert_eq!(saved.data::<serde_json::Value>(), maximum);
    });
}

#[test]
#[serial]
fn type_import_rejects_native_dropped_components_without_saving_partial_declarations() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:32:default");
    let client = harness().client().unwrap();
    super::common::with_temporary_program(&client, &program, TEST_PROGRAM, || {
        let before = type_command(&program, &["list", "--limit", "0"]);
        before.assert_success();
        let before: serde_json::Value = before.data();
        let rejected = type_command(
            &program,
            &[
                "import-c",
                "--code",
                "struct DroppedComponent { short bytes[1073741824]; int retained; };",
            ],
        );
        rejected
            .assert_failure()
            .assert_stderr_contains("C parser discarded a field");
        let error: serde_json::Value = serde_json::from_str(&rejected.stderr).unwrap();
        assert_eq!(error["detail"]["rolled_back"], true, "{error}");
        let after = type_command(&program, &["list", "--limit", "0"]);
        after.assert_success();
        assert_eq!(after.data::<serde_json::Value>(), before);
        client.program_close().unwrap();
        let saved = type_command(&program, &["list", "--limit", "0"]);
        saved.assert_success();
        assert_eq!(saved.data::<serde_json::Value>(), before);
        type_command(
            &program,
            &[
                "import-c",
                "--code",
                "struct CompleteComponent { short bytes[16]; int retained; };",
            ],
        )
        .assert_success();
        let complete = type_command(&program, &["get", "/CompleteComponent"]);
        complete.assert_success();
        let complete: serde_json::Value = complete.data();
        assert_eq!(complete["size"], 36);
        assert_eq!(complete["components"][0]["name"], "bytes");
        assert_eq!(complete["components"][0]["size"], 32);
        assert_eq!(complete["components"][1]["name"], "retained");
        assert_eq!(complete["components"][1]["offset"], 32);
        client.program_close().unwrap();
        assert_eq!(
            type_command(&program, &["get", "/CompleteComponent"]).data::<serde_json::Value>(),
            complete
        );
    });
}

#[test]
#[serial]
fn type_import_rejects_native_clipped_bitfields_without_changing_saved_definitions() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    let client = harness().client().unwrap();
    super::common::with_temporary_program(&client, &program, TEST_PROGRAM, || {
        type_command(
            &program,
            &["import-c", "--code", "struct Existing { int original; };"],
        )
        .assert_success();
        let before = type_command(&program, &["get", "/Existing"]).data::<serde_json::Value>();
        let listed = type_command(&program, &["list", "--limit", "0"]).data::<serde_json::Value>();
        for declaration in [
            "struct Clipped { unsigned int bits : 64; };",
            "struct Clipped { struct { unsigned char bits : 9; } *entry; };",
        ] {
            let code = format!("struct Existing {{ char changed; }}; {declaration}");
            let failed = type_command(&program, &["import-c", "--code", &code]);
            failed
                .assert_failure()
                .assert_stderr_contains("Bit-field width");
            let error: serde_json::Value = serde_json::from_str(&failed.stderr).unwrap();
            assert_eq!(error["detail"]["rolled_back"], true, "{error}");
            client.program_close().unwrap();
            assert_eq!(
                type_command(&program, &["get", "/Existing"]).data::<serde_json::Value>(),
                before
            );
            assert_eq!(
                type_command(&program, &["list", "--limit", "0"]).data::<serde_json::Value>(),
                listed
            );
        }
        type_command(&program, &["import-c", "--code", "struct CompleteBits { unsigned int full : 32; unsigned int : 0; unsigned char small : 3; };"])
            .assert_success();
        let complete =
            type_command(&program, &["get", "/CompleteBits"]).data::<serde_json::Value>();
        let fields = complete["components"].as_array().unwrap();
        for (name, width) in [("full", 32), ("small", 3)] {
            assert_eq!(
                fields.iter().find(|field| field["name"] == name).unwrap()["bit_size"],
                width
            );
        }
        client
            .script_run_source(
                include_str!("../fixtures/types/CreateExistingOverwideDependency.java"),
                &[],
                &[],
                false,
            )
            .unwrap();
        let existing = type_command(&program, &["get", "/Source/ExistingOverwide"])
            .data::<serde_json::Value>();
        type_command(&program, &["import-c", "--code", "typedef struct ExistingOverwide *ExistingOverwidePointer; struct UsesExistingOverwide { struct ExistingOverwide value; };"])
            .assert_success();
        type_command(&program, &["import-c", "--code", "struct ExistingOverwide { int value; }; struct UsesExistingContainer { struct ExistingContainer value; };"])
            .assert_success();
        client.program_close().unwrap();
        assert_eq!(
            type_command(&program, &["get", "/CompleteBits"]).data::<serde_json::Value>(),
            complete
        );
        assert_eq!(
            type_command(&program, &["get", "/Source/ExistingOverwide"])
                .data::<serde_json::Value>(),
            existing
        );
        let uses =
            type_command(&program, &["get", "/UsesExistingOverwide"]).data::<serde_json::Value>();
        assert_eq!(
            uses["components"][0]["type_path"],
            "/Source/ExistingOverwide"
        );
    });
}

#[test]
#[serial]
fn type_import_rejects_colliding_definitions_without_changing_users() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    type_command(
        &program,
        &[
            "import-c",
            "--code",
            "struct Item { int original; int tail; }; struct Holder { struct Item item; };",
        ],
    )
    .assert_success();
    let client = harness().client().unwrap();
    let fixture = include_str!("../fixtures/types/CheckCImportNamespaceCollision.java");
    client
        .script_run_source(fixture, &["setup".into()], &[], false)
        .unwrap();
    let paths = ["/Item", "/Holder"];
    let before: Vec<serde_json::Value> = paths
        .iter()
        .map(|path| type_command(&program, &["get", path]).data())
        .collect();
    let before_types: serde_json::Value = type_command(&program, &["list", "--limit", "0"]).data();
    let namespace_collision = "struct Fresh { int marker; }; struct Item { long long changed; }; \
        typedef int Item; struct Holder { struct Item item; };";
    for (code, category) in [
        (namespace_collision, None),
        (namespace_collision, Some("/Draft")),
        (
            "struct Fresh { int marker; }; struct Item { int first; }; \
             struct Holder { struct Item item; }; struct Item { short second; };",
            Some("/Draft"),
        ),
    ] {
        let mut args = vec!["import-c", "--code", code];
        if let Some(category) = category {
            args.extend(["--category", category]);
        }
        let failed = type_command(&program, &args);
        failed
            .assert_failure()
            .assert_stderr_contains("conflict")
            .assert_stderr_contains("/Item");
        let error: serde_json::Value = serde_json::from_str(&failed.stderr).unwrap();
        assert_eq!(error["detail"]["rolled_back"], true, "{error}");

        for reopen in [false, true] {
            if reopen {
                client.program_close().unwrap();
                client.open_program(&program).unwrap();
            }
            assert_eq!(
                type_command(&program, &["list", "--limit", "0"]).data::<serde_json::Value>(),
                before_types
            );
            for (path, expected) in paths.iter().zip(&before) {
                assert_eq!(
                    &type_command(&program, &["get", path]).data::<serde_json::Value>(),
                    expected,
                    "{path}"
                );
            }
            client
                .script_run_source(fixture, &["check".into()], &[], false)
                .unwrap();
        }
    }
    client.open_program(TEST_PROGRAM).unwrap();
}

#[test]
#[serial]
fn type_import_rejects_ambiguous_external_references_and_keeps_local_definitions() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    for (category, code) in [
        ("/zeta", "struct Shared { long long second; };"),
        ("/alpha", "struct Shared { int first; };"),
    ] {
        type_command(
            &program,
            &["import-c", "--category", category, "--code", code],
        )
        .assert_success();
    }
    let client = harness().client().unwrap();
    let before: serde_json::Value = type_command(&program, &["list", "--limit", "0"]).data();
    let paths = ["/alpha/Shared", "/zeta/Shared"];
    let definitions: Vec<serde_json::Value> = paths
        .iter()
        .map(|path| type_command(&program, &["get", path]).data())
        .collect();

    for declaration in ["typedef Shared Alias;", "typedef struct Shared *Alias;"] {
        let code = format!("struct Fresh {{ int marker; }}; {declaration}");
        let failed = type_command(
            &program,
            &["import-c", "--category", "/Draft", "--code", &code],
        );
        failed
            .assert_failure()
            .assert_stderr_contains("Ambiguous type name");
        let error: serde_json::Value = serde_json::from_str(&failed.stderr).unwrap();
        assert_eq!(error["detail"]["rolled_back"], true, "{error}");
        assert_eq!(
            error["detail"]["candidates"],
            serde_json::json!(["/alpha/Shared", "/zeta/Shared"]),
            "{error}"
        );
        client.program_close().unwrap();
        assert_eq!(
            type_command(&program, &["list", "--limit", "0"]).data::<serde_json::Value>(),
            before
        );
        for (path, expected) in paths.iter().zip(&definitions) {
            assert_eq!(
                &type_command(&program, &["get", path]).data::<serde_json::Value>(),
                expected
            );
        }
    }

    // Local forward uses bind to the later body; the field named Shared is not a type lookup.
    type_command(
        &program,
        &[
            "import-c",
            "--category",
            "/Draft",
            "--code",
            "struct Shared; struct EarlyHolder { struct Shared *next; }; \
             struct Shared { short local; }; typedef struct Shared Alias; \
             typedef int Local; struct Holder { Local Shared; };",
        ],
    )
    .assert_success();
    client.program_close().unwrap();
    let alias: serde_json::Value = type_command(&program, &["get", "/Draft/Alias"]).data();
    assert_eq!(alias["base_type_path"], "/Draft/Shared");
    let shared: serde_json::Value = type_command(&program, &["get", "/Draft/Shared"]).data();
    assert_eq!(shared["components"][0]["name"], "local");
    let early: serde_json::Value = type_command(&program, &["get", "/Draft/EarlyHolder"]).data();
    assert_eq!(early["components"][0]["type_path"], "/Draft/Shared *");
    let holder: serde_json::Value = type_command(&program, &["get", "/Draft/Holder"]).data();
    assert_eq!(holder["components"][0]["name"], "Shared");
    for (path, expected) in paths.iter().zip(&definitions) {
        assert_eq!(
            &type_command(&program, &["get", path]).data::<serde_json::Value>(),
            expected
        );
    }
    client.open_program(TEST_PROGRAM).unwrap();
}

#[test]
#[serial]
fn type_import_tagged_references_preserve_existing_definitions_and_applied_data() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    type_command(
        &program,
        &[
            "import-c",
            "--category",
            "/Existing",
            "--code",
            "struct Record { int value; int tail; }; \
             union Payload { int value; long long wide; }; enum Status { GOOD=1, BAD=2 };",
        ],
    )
    .assert_success();
    let client = harness().client().unwrap();
    let fixture = include_str!("../fixtures/types/CheckTaggedImportReferences.java");
    client
        .script_run_source(fixture, &["setup".into()], &[], false)
        .unwrap();
    let paths = ["/Existing/Record", "/Existing/Payload", "/Existing/Status"];
    let before: Vec<serde_json::Value> = paths
        .iter()
        .map(|path| type_command(&program, &["get", path]).data())
        .collect();
    for code in [
        "typedef struct Status *BadStatus;",
        "typedef struct Payload *BadPayload;",
    ] {
        type_command(
            &program,
            &["import-c", "--category", "/Existing", "--code", code],
        )
        .assert_failure()
        .assert_stderr_contains("C tag kind does not match registered type");
        client.program_close().unwrap();
        for (path, expected) in paths.iter().zip(&before) {
            assert_eq!(
                &type_command(&program, &["get", path]).data::<serde_json::Value>(),
                expected
            );
        }
    }
    type_command(
        &program,
        &[
            "import-c",
            "--category",
            "/Draft",
            "--code",
            "typedef struct Record *RecordPtr; typedef union Payload PayloadAlias; \
             typedef enum Status StatusAlias; \
             struct Holder { struct Record record; union Payload payload; enum Status status; };",
        ],
    )
    .assert_success();
    client.program_close().unwrap();
    for (path, expected) in paths.iter().zip(&before) {
        assert_eq!(
            &type_command(&program, &["get", path]).data::<serde_json::Value>(),
            expected
        );
    }
    client
        .script_run_source(fixture, &["check".into()], &[], false)
        .unwrap();
    client.open_program(TEST_PROGRAM).unwrap();
}

#[test]
#[serial]
fn type_import_category_preserves_root_types_and_users_after_reopen() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    let root_code = "typedef int Scalar; \
        struct Item { int original; struct { int inner; } nested; }; \
        typedef struct Item ItemAlias; typedef struct Item ExistingAlias; \
        struct Holder { struct Item item; }; \
        typedef int (*Callback)(struct Item *);";
    type_command(&program, &["import-c", "--code", root_code]).assert_success();
    let client = harness().client().unwrap();
    let fixture = include_str!("../fixtures/types/CheckImportCategory.java");
    client
        .script_run_source(fixture, &["setup".to_string()], &[], false)
        .unwrap();

    let paths = [
        "/Item",
        "/ItemAlias",
        "/ExistingAlias",
        "/Holder",
        "/Scalar",
        "/Callback",
    ];
    let before: Vec<serde_json::Value> = paths
        .iter()
        .map(|path| {
            let result = type_command(&program, &["get", path]);
            result.assert_success();
            result.data()
        })
        .collect();

    for (category, member_type, field, size) in [
        ("/Equal", "int", "original", 8),
        ("/Draft", "char", "replacement", 2),
        ("/Draft", "short", "replacement", 4),
    ] {
        let code = format!(
            "struct Item {{ {member_type} {field}; struct {{ {member_type} inner; }} nested; }}; \
             typedef struct Item ItemAlias; struct Holder {{ struct Item item; }}; \
             typedef int (*Callback)(struct Item *); \
             typedef ExistingAlias ImportedAlias; \
             struct Link {{ struct Link *next; Scalar key; struct Item item; }};"
        );
        let result = type_command(
            &program,
            &["import-c", "--category", category, "--code", &code],
        );
        result.assert_success();
        let receipt: serde_json::Value = result.data();
        let item = receipt["types"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["name"] == "Item")
            .unwrap();
        assert_eq!(item["path"], format!("{category}/Item"));
        assert_eq!(item["size"], size);

        for reopen in [false, true] {
            if reopen {
                client.program_close().unwrap();
                client.open_program(&program).unwrap();
            }
            for (path, expected) in paths.iter().zip(&before) {
                let result = type_command(&program, &["get", path]);
                result.assert_success();
                assert_eq!(&result.data::<serde_json::Value>(), expected, "{path}");
            }
            client
                .script_run_source(
                    fixture,
                    &[category.to_string(), field.to_string(), size.to_string()],
                    &[],
                    false,
                )
                .unwrap();
        }
    }
    client.open_program(TEST_PROGRAM).unwrap();
}

#[test]
#[serial]
fn test_type_import_c_category_keeps_existing_same_named_types() {
    require_ghidra!();
    let harness = harness();

    let suffix = unique_suffix();
    let type_name = format!("CatIsoType_{}", suffix);
    let category_a = format!("/cat_a_{}", suffix);
    let category_b = format!("/cat_b_{}", suffix);
    let def_a = format!("struct {} {{ int a; }};", type_name);
    let def_b = format!("struct {} {{ int b; }};", type_name);

    ghidra(harness)
        .arg("type")
        .arg("import-c")
        .arg("--category")
        .arg(&category_a)
        .arg("--code")
        .arg(&def_a)
        .with_project(test_project(), TEST_PROGRAM)
        .run()
        .assert_success();

    ghidra(harness)
        .arg("type")
        .arg("import-c")
        .arg("--category")
        .arg(&category_b)
        .arg("--code")
        .arg(&def_b)
        .with_project(test_project(), TEST_PROGRAM)
        .run()
        .assert_success();

    let list_result = ghidra(harness)
        .arg("type")
        .arg("list")
        .arg("--filter")
        .arg(format!("name={type_name}"))
        .with_project(test_project(), TEST_PROGRAM)
        .json_format()
        .run();

    list_result.assert_success();
    let listed_types: Vec<serde_json::Value> = list_result.data();

    let categories: HashSet<String> = listed_types
        .iter()
        .filter(|item| item.get("name").and_then(|v| v.as_str()) == Some(type_name.as_str()))
        .filter_map(|item| item.get("category").and_then(|v| v.as_str()))
        .map(|s| s.to_string())
        .collect();

    assert!(
        categories.contains(&category_a),
        "Expected {} to remain after second import. Seen categories: {:?}",
        category_a,
        categories
    );
    assert!(
        categories.contains(&category_b),
        "Expected {} after second import. Seen categories: {:?}",
        category_b,
        categories
    );
}
