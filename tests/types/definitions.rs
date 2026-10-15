use super::{create_type_edit_program, harness, type_command, TEST_PROGRAM};
use serde_json::{json, Value};
use serial_test::serial;

fn command(program: &str, args: &[&str]) -> Value {
    let result = type_command(program, args);
    result.assert_success();
    result.data()
}

fn definition(program: &str, name: &str) -> Value {
    command(program, &["get", name])
}

fn run_script(program: &str, source: &str, args: &[String]) {
    let client = harness().client().unwrap();
    client.open_program(program).unwrap();
    client.script_run_source(source, args, &[], false).unwrap();
}

fn reopen(program: &str) {
    let client = harness().client().unwrap();
    client.program_close().unwrap();
    client.open_program(program).unwrap();
}

fn description_fixture() -> String {
    let program = create_type_edit_program("x86:LE:64:default");
    run_script(
        &program,
        include_str!("../fixtures/types/CreateDescriptionTypes.java"),
        &[],
    );
    program
}

#[test]
#[serial]
fn descriptions_update_clear_and_preserve_saved_layout_identity_and_uses() {
    require_ghidra!();
    let program = description_fixture();
    let holder = definition(&program, "/Descriptions/Holder");
    let other = definition(&program, "/Other/Node");
    let text = "説明\n  partial layout; trailing spaces  ";
    for path in [
        "/Descriptions/Node",
        "/Descriptions/Choice",
        "/Descriptions/Mode",
    ] {
        let mut expected = definition(&program, path);
        let before = expected["description"].clone();
        let updated = command(&program, &["set-description", path, "--text", text]);
        assert_eq!(updated["path"], path);
        assert_eq!(updated["status"], "updated");
        assert_eq!(updated["changed"], true);
        assert_eq!(updated["before"], before);
        assert_eq!(updated["after"], text);
        expected["description"] = json!(text);
        reopen(&program);
        assert_eq!(definition(&program, path), expected);

        for value in [text, ""] {
            if value.is_empty() {
                let cleared = command(&program, &["set-description", path, "--text", ""]);
                assert_eq!(cleared["before"], text);
                assert_eq!(cleared["after"], "");
                assert_eq!(cleared["changed"], true);
                expected["description"] = json!("");
                reopen(&program);
                assert_eq!(definition(&program, path), expected);
            }
            let client = harness().client().unwrap();
            let guard =
                || client.send_command("type_gdt_candidates", None).unwrap()["source"].clone();
            let before = guard();
            let unchanged = command(&program, &["set-description", path, "--text", value]);
            assert_eq!(unchanged["status"], "unchanged");
            assert_eq!(unchanged["changed"], false);
            assert_eq!(unchanged["before"], value);
            assert_eq!(unchanged["after"], value);
            assert_eq!(guard(), before, "same-value edit changed the Program");
        }
        assert_eq!(definition(&program, "/Descriptions/Holder"), holder);
        assert_eq!(definition(&program, "/Other/Node"), other);
    }
    reopen(&program);
    run_script(
        &program,
        include_str!("../fixtures/types/CheckDescriptionUses.java"),
        &[],
    );
    harness()
        .client()
        .unwrap()
        .open_program(TEST_PROGRAM)
        .unwrap();
}

#[test]
#[serial]
fn descriptions_reject_ambiguous_unsupported_and_invalid_edits_without_changes() {
    require_ghidra!();
    let program = description_fixture();
    let paths = [
        "/Descriptions/Node",
        "/Other/Node",
        "/Descriptions/Alias",
        "/Descriptions/Callback",
    ];
    let before: Vec<_> = paths
        .iter()
        .map(|path| definition(&program, path))
        .collect();
    for name in [
        "Node",
        "/Descriptions/Alias",
        "/Descriptions/Callback",
        "/dword",
        "/Missing",
    ] {
        let result = type_command(
            &program,
            &["set-description", name, "--text", "must not change"],
        );
        result.assert_failure();
    }
    let client = harness().client().unwrap();
    for args in [
        json!({"type_name": "/Descriptions/Node"}),
        json!({"type_name": "/Descriptions/Node", "text": null}),
        json!({"type_name": "/Descriptions/Node", "text": 42}),
    ] {
        assert!(client
            .send_command("type_set_description", Some(args))
            .is_err());
    }
    reopen(&program);
    for (path, expected) in paths.iter().zip(before) {
        assert_eq!(definition(&program, path), expected);
    }
    harness()
        .client()
        .unwrap()
        .open_program(TEST_PROGRAM)
        .unwrap();
}

#[test]
#[serial]
fn get_imported_and_cloned_function_definitions_exposes_saved_signatures() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    command(
        &program,
        &[
            "import-c",
            "--code",
            "int __cdecl ImportedCallback(int count, char *message, ...); void EmptyCallback(void);",
        ],
    );
    let original = definition(&program, "ImportedCallback");
    assert_eq!(original["kind"], "functiondef");
    assert_eq!(original["calling_convention"], "__cdecl");
    assert_eq!(original["variadic"], true);
    assert_eq!(original["no_return"], false);
    assert_eq!(
        original["return"],
        json!({"type": "int", "type_path": "/int", "size": 4})
    );
    let parameters = original["params"].as_array().unwrap();
    assert_eq!(parameters.len(), 2);
    for (ordinal, (name, type_name, size)) in [("count", "int", 4), ("message", "char *", 8)]
        .into_iter()
        .enumerate()
    {
        assert_eq!(parameters[ordinal]["ordinal"], ordinal);
        assert_eq!(parameters[ordinal]["name"], name);
        assert_eq!(parameters[ordinal]["type"], type_name);
        assert_eq!(parameters[ordinal]["type_path"], format!("/{type_name}"));
        assert_eq!(parameters[ordinal]["size"], size);
    }
    let empty = definition(&program, "EmptyCallback");
    assert_eq!(empty["return"]["type"], "void");
    assert_eq!(empty["params"], json!([]));
    assert_eq!(empty["variadic"], false);

    let receipt = command(
        &program,
        &[
            "clone",
            original["path"].as_str().unwrap(),
            "ClonedCallback",
        ],
    );
    reopen(&program);
    assert_eq!(definition(&program, "ImportedCallback"), original);
    let cloned = definition(&program, receipt["path"].as_str().unwrap());
    for key in [
        "return",
        "params",
        "calling_convention",
        "variadic",
        "no_return",
    ] {
        assert_eq!(cloned[key], original[key], "{key}");
    }
    harness()
        .client()
        .unwrap()
        .open_program(TEST_PROGRAM)
        .unwrap();
}

#[test]
#[serial]
fn clone_composites_preserves_saved_layout_settings_and_shared_external_dependencies() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    let archive_dir = tempfile::tempdir().unwrap();
    let archive_path = archive_dir.path().join("Recovered.gdt");
    run_script(
        &program,
        include_str!("../fixtures/types/CreateCloneDefinitions.java"),
        &[archive_path.to_string_lossy().into_owned()],
    );
    let payload_before = definition(&program, "/Source/Payload");
    assert_eq!(payload_before["source_archive"]["kind"], "file");
    command(&program, &["category", "create", "/Draft"]);
    let names = ["Node", "Packed", "Union", "PackedUnion"];
    let originals: Vec<_> = names
        .iter()
        .map(|name| definition(&program, &format!("/Source/{name}")))
        .collect();
    for (name, original) in names.iter().zip(&originals) {
        let cloned = command(
            &program,
            &[
                "clone",
                &format!("/Source/{name}"),
                &format!("{name}Copy"),
                "--category",
                "/Draft",
            ],
        );
        assert_eq!(cloned["source_path"], format!("/Source/{name}"));
        assert_eq!(cloned["path"], format!("/Draft/{name}Copy"));
        assert_eq!(cloned["status"], "cloned");
        let copied = definition(&program, &format!("/Draft/{name}Copy"));
        assert_ne!(copied["universal_id"], original["universal_id"]);
        assert!(copied["universal_id"].is_string());
        assert_eq!(copied["source_archive"]["kind"], "program");
        assert_ne!(
            copied["source_archive"]["id"],
            original["source_archive"]["id"]
        );
        for key in ["size", "description", "packing_enabled", "components"] {
            assert_eq!(copied[key], original[key], "{name}: {key}");
        }
        assert_eq!(definition(&program, &format!("/Source/{name}")), *original);
    }
    assert_eq!(definition(&program, "/Source/Payload"), payload_before);
    reopen(&program);
    for (name, original) in names.iter().zip(&originals) {
        assert_eq!(definition(&program, &format!("/Source/{name}")), *original);
    }
    run_script(
        &program,
        include_str!("../fixtures/types/CheckSavedClonedDefinitions.java"),
        &[],
    );
    reopen(&program);
    assert_eq!(
        definition(&program, "/Source/Payload")["components"][0]["name"],
        "shared_edit"
    );
    assert_eq!(
        definition(&program, "/Source/Node")["components"],
        originals[0]["components"]
    );
    harness()
        .client()
        .unwrap()
        .open_program(TEST_PROGRAM)
        .unwrap();
}

#[test]
#[serial]
fn clone_enum_typedef_and_function_preserves_definition_settings_and_default_category() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    run_script(
        &program,
        include_str!("../fixtures/types/CreateOtherCloneDefinitions.java"),
        &[],
    );
    let names = ["Values", "Alias", "Relative", "Callback"];
    let originals: Vec<_> = names
        .iter()
        .map(|name| definition(&program, &format!("/Types/{name}")))
        .collect();
    let callback = &originals[3];
    assert_eq!(callback["comment"], "callback comment");
    assert_eq!(callback["calling_convention"], "__cdecl");
    assert_eq!(callback["variadic"], true);
    assert_eq!(callback["no_return"], true);
    assert_eq!(
        callback["return"],
        json!({"type": "Alias", "type_path": "/Types/Alias", "size": 4})
    );
    assert_eq!(
        callback["params"],
        json!([{
            "ordinal": 0,
            "name": "arg",
            "type": "Relative",
            "type_path": "/Types/Relative",
            "size": 8,
            "comment": "argument comment"
        }])
    );
    for name in names {
        let receipt = command(
            &program,
            &["clone", &format!("/Types/{name}"), &format!("{name}Copy")],
        );
        assert_eq!(receipt["path"], format!("/Types/{name}Copy"));
    }
    reopen(&program);
    let cloned_callback = definition(&program, "/Types/CallbackCopy");
    for key in [
        "comment",
        "calling_convention",
        "variadic",
        "no_return",
        "return",
        "params",
    ] {
        assert_eq!(cloned_callback[key], callback[key], "{key}");
    }
    run_script(
        &program,
        include_str!("../fixtures/types/CheckOtherClonedDefinitions.java"),
        &[],
    );
    for (name, original) in names.iter().zip(&originals) {
        assert_eq!(definition(&program, &format!("/Types/{name}")), *original);
    }
    harness()
        .client()
        .unwrap()
        .open_program(TEST_PROGRAM)
        .unwrap();
}

#[test]
#[serial]
fn categories_and_move_preserve_identity_references_and_reject_destructive_collisions() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    command(&program, &["category", "create", "/Draft/Empty"]);
    assert_eq!(
        command(&program, &["category", "create", "/Draft/Empty"])["changed"],
        false
    );
    assert_eq!(
        command(&program, &["category", "create", "/"])["changed"],
        false
    );
    command(&program, &["category", "create", "/Final"]);
    command(
        &program,
        &[
            "import-c",
            "--code",
            "struct Item { int value; };",
            "--category",
            "/Draft",
        ],
    );
    command(
        &program,
        &[
            "import-c",
            "--code",
            "struct Item { char existing; };",
            "--category",
            "/Final",
        ],
    );
    let children = type_command(&program, &["category", "list", "/Draft"]);
    children.assert_success();
    assert_eq!(
        children.data::<Value>(),
        json!([{"name": "Empty", "path": "/Draft/Empty", "type_count": 0}])
    );
    assert_eq!(children.json::<Value>()["meta"]["path"], "/Draft");
    let categories = command(&program, &["category", "list", "/"]);
    for name in ["Draft", "Final"] {
        let category = categories
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["name"] == name)
            .unwrap();
        assert_eq!(category["type_count"], 1);
    }
    assert!(command(&program, &["category", "list", "/Draft/Empty"])
        .as_array()
        .unwrap()
        .is_empty());
    command(
        &program,
        &["create", "typedef", "ItemAlias", "--type", "/Draft/Item *"],
    );
    let alias = definition(&program, "/ItemAlias");
    let pointer_path = alias["base_type_path"].as_str().unwrap();
    type_command(&program, &["move", pointer_path, "--category", "/Final"])
        .assert_failure()
        .assert_stderr_contains("editable named definition");
    assert_eq!(definition(&program, "/ItemAlias"), alias);
    let source = definition(&program, "/Draft/Item");
    let collision = definition(&program, "/Final/Item");
    let clone_collision = type_command(
        &program,
        &["clone", "/Draft/Item", "Item", "--category", "/Final"],
    );
    clone_collision
        .assert_failure()
        .assert_stderr_contains("already exists");
    assert_eq!(
        serde_json::from_str::<Value>(&clone_collision.stderr).unwrap()["detail"]["rolled_back"],
        true
    );
    type_command(&program, &["move", "/Draft/Item", "--category", "/Final"])
        .assert_failure()
        .assert_stderr_contains("already exists");
    type_command(
        &program,
        &[
            "clone",
            "/Draft/Item",
            "MissingCopy",
            "--category",
            "/Missing",
        ],
    )
    .assert_failure()
    .assert_stderr_contains("Category not found");
    type_command(&program, &["move", "/Draft/Item", "--category", "/Missing"])
        .assert_failure()
        .assert_stderr_contains("Category not found");
    for path in ["/", "/Draft", "/Final"] {
        type_command(&program, &["category", "delete", path]).assert_failure();
    }
    for path in ["Relative", "/Bad/../Target", "/Bad//Target", "/Bad/"] {
        type_command(&program, &["category", "create", path]).assert_failure();
    }
    reopen(&program);
    assert_eq!(definition(&program, "/Draft/Item"), source);
    assert_eq!(definition(&program, "/Final/Item"), collision);
    let unchanged = command(&program, &["move", "/Draft/Item", "--category", "/Draft"]);
    assert_eq!(unchanged["changed"], false);
    assert_eq!(unchanged["old_path"], "/Draft/Item");
    command(&program, &["rename", "/Draft/Item", "MovedItem"]);
    assert_eq!(
        definition(&program, "/Draft/MovedItem")["universal_id"],
        source["universal_id"]
    );
    let moved = command(
        &program,
        &["move", "/Draft/MovedItem", "--category", "/Final"],
    );
    assert_eq!(moved["old_path"], "/Draft/MovedItem");
    assert_eq!(moved["path"], "/Final/MovedItem");
    assert_eq!(moved["changed"], true);
    command(&program, &["category", "delete", "/Draft/Empty"]);
    reopen(&program);
    let after = definition(&program, "/Final/MovedItem");
    assert_eq!(after["universal_id"], source["universal_id"]);
    assert_eq!(after["source_archive"], source["source_archive"]);
    let primitive = definition(&program, "int");
    assert!(primitive["universal_id"].is_null());
    assert_eq!(primitive["source_archive"]["kind"], "built_in");
    type_command(&program, &["get", "/Draft/Item"]).assert_failure();
    run_script(
        &program,
        include_str!("../fixtures/types/CheckMovedTypeReferences.java"),
        &[],
    );
    harness()
        .client()
        .unwrap()
        .open_program(TEST_PROGRAM)
        .unwrap();
}

#[test]
#[serial]
fn overdeep_category_paths_fail_before_native_mutation_and_keep_bridge_running() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    command(&program, &["create", "struct", "Anchor"]);
    // Escaped slashes belong to one category name, not additional ancestors.
    let escaped = format!("/{}tail", "part\\/".repeat(160));
    assert_eq!(
        command(&program, &["category", "create", &escaped])["path"],
        escaped
    );
    command(&program, &["category", "delete", &escaped]);
    let before = definition(&program, "/Anchor");
    let categories = command(&program, &["category", "list", "/"]);
    let client = harness().client().unwrap();
    let error = client
        .send_command(
            "type_category_create",
            Some(json!({"path": "/nested".repeat(10_000)})),
        )
        .expect_err("overdeep category path was accepted");
    assert!(
        error.to_string().contains("Type path nesting exceeds"),
        "{error:#}"
    );
    client.program_info().unwrap();
    reopen(&program);
    assert_eq!(definition(&program, "/Anchor"), before);
    assert_eq!(command(&program, &["category", "list", "/"]), categories);
    client.open_program(TEST_PROGRAM).unwrap();
}
