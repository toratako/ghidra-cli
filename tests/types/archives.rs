use super::{create_type_edit_program, harness, type_command, TEST_PROGRAM};
use crate::common::ghidra;
use serde_json::{json, Value};
use serial_test::serial;
use std::path::Path;

const ROOT: &str = "/Gdt/Root";
const NAMES: &[&str] = &[
    "Root", "Node", "Link", "Payload", "Choice", "Alias", "Callback", "Mode",
];

fn command(program: &str, args: &[&str]) -> Value {
    let result = type_command(program, args);
    result.assert_success();
    result.data()
}

fn fixture(program: &str, mode: &str, file: &Path) {
    let client = harness().client().unwrap();
    client.open_program(program).unwrap();
    client
        .script_run_source(
            include_str!("GdtArchiveFixture.java"),
            &[mode.into(), file.to_string_lossy().into_owned()],
            &[],
            false,
        )
        .unwrap();
}

fn reopen(program: &str) {
    let client = harness().client().unwrap();
    client.program_close().unwrap();
    client.open_program(program).unwrap();
}

fn restore_program() {
    harness()
        .client()
        .unwrap()
        .open_program(TEST_PROGRAM)
        .unwrap();
}

fn list(program: &str) -> Value {
    command(program, &["list", "--limit", "0", "--sort", "path"])
}

fn definitions(program: &str) -> Vec<Value> {
    NAMES
        .iter()
        .map(|name| command(program, &["get", &format!("/Gdt/{name}")]))
        .collect()
}

fn candidates(file: Option<&Path>) -> Value {
    harness()
        .client()
        .unwrap()
        .send_command(
            "type_gdt_candidates",
            file.map(|file| json!({"file": file})),
        )
        .unwrap()
}

fn packed_database_cache_entries() -> Vec<String> {
    let result = harness()
        .client()
        .unwrap()
        .script_run_source(
            include_str!("GdtArchiveFixture.java"),
            &["packed-cache-state".into(), String::new()],
            &[],
            false,
        )
        .unwrap();
    serde_json::from_str(result["stdout"].as_str().unwrap().trim()).unwrap()
}

#[test]
#[serial]
fn archive_list_queries_a_read_only_file_without_a_loaded_program() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("source with 'quotes'.gdt");
    fixture(&program, "create", &file);
    let original_bytes = std::fs::read(&file).unwrap();
    // Fixture creation may legitimately populate Ghidra's persistent cache.
    // Compare actual database directories, including orphans absent from cache.map.
    let cache_before = packed_database_cache_entries();
    let client = harness().client().unwrap();
    client.program_close().unwrap();
    let result = ghidra(harness())
        .args(["type", "archive", "list"])
        .arg(file.to_string_lossy())
        .args([
            "--filter",
            r#"category="/Gdt""#,
            "--sort",
            "path",
            "--fields",
            "name,path,kind,size,universal_id,source_archive",
            "--limit",
            "0",
            "--json",
        ])
        .run();
    result.assert_success();
    let rows: Vec<Value> = result.data();
    assert_eq!(rows.len(), NAMES.len());
    assert!(rows
        .windows(2)
        .all(|pair| pair[0]["path"].as_str() < pair[1]["path"].as_str()));
    let root = rows.iter().find(|row| row["path"] == ROOT).unwrap();
    assert_eq!(root["kind"], "struct");
    assert_eq!(root["size"], 48);
    assert!(root["universal_id"].is_string());
    assert_eq!(root["source_archive"]["kind"], "file");
    let count = ghidra(harness())
        .args(["type", "archive", "list"])
        .arg(file.to_string_lossy())
        .args(["--filter", "kind=struct", "--count", "--json"])
        .run();
    count.assert_success();
    assert_eq!(count.data::<Value>(), 5);
    assert!(
        client.program_info().is_err(),
        "Archive listing selected a Program"
    );
    client.open_program(&program).unwrap();
    assert_eq!(packed_database_cache_entries(), cache_before);
    for index in 0..2 {
        client
            .send_command("type_archive_list", Some(json!({"file": file})))
            .unwrap();
        candidates(Some(&file));
        command(&program, &["import-gdt", file.to_str().unwrap(), "--all"]);
        let exported = directory.path().join(format!("cache-check-{index}.gdt"));
        command(
            &program,
            &["export-gdt", exported.to_str().unwrap(), "--all"],
        );
        candidates(Some(&exported));
        assert_eq!(
            packed_database_cache_entries(),
            cache_before,
            "Archive operation cycle {index} changed the persistent packed database cache"
        );
    }
    assert_eq!(std::fs::read(&file).unwrap(), original_bytes);
    restore_program();
}

#[test]
#[serial]
fn selected_import_roundtrips_shared_recursive_dependencies_and_reuses_them() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("source.gdt");
    let exported = directory.path().join("exported.gdt");
    fixture(&program, "create", &file);
    let original_bytes = std::fs::read(&file).unwrap();
    let receipt = command(
        &program,
        &[
            "import-gdt",
            file.to_str().unwrap(),
            "--where",
            r#"path="/Gdt/Root""#,
        ],
    );
    assert_eq!(receipt["roots"], json!([ROOT]));
    let dependencies = receipt["dependencies"].as_array().unwrap();
    for name in &NAMES[1..] {
        assert!(
            dependencies.contains(&json!(format!("/Gdt/{name}"))),
            "{receipt}"
        );
    }
    type_command(&program, &["get", "/Other/Unselected"]).assert_failure();
    fixture(&program, "check-import", &file);
    let before = list(&program);
    let before_definitions = definitions(&program);
    let repeated = command(
        &program,
        &[
            "import-gdt",
            file.to_str().unwrap(),
            "--where",
            r#"path="/Gdt/Root""#,
        ],
    );
    assert_eq!(repeated["changed"], false, "{repeated}");
    assert_eq!(list(&program), before);
    reopen(&program);
    assert_eq!(definitions(&program), before_definitions);
    fixture(&program, "check-import", &file);

    let source_before = candidates(None)["source"].clone();
    command(
        &program,
        &[
            "export-gdt",
            exported.to_str().unwrap(),
            "--where",
            r#"path="/Gdt/Root""#,
        ],
    );
    assert_eq!(candidates(None)["source"], source_before);
    assert_eq!(definitions(&program), before_definitions);
    fixture(&program, "check-export", &exported);
    reopen(&program);
    assert_eq!(definitions(&program), before_definitions);
    assert_eq!(std::fs::read(&file).unwrap(), original_bytes);

    let target = create_type_edit_program("x86:LE:64:default");
    command(
        &target,
        &["import-gdt", exported.to_str().unwrap(), "--all"],
    );
    reopen(&target);
    fixture(&target, "check-import", &file);
    assert_eq!(definitions(&target), before_definitions);
    restore_program();
}

#[test]
#[serial]
fn all_import_includes_unrelated_roots_and_equivalent_local_types_adopt_origin() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("source.gdt");
    fixture(&program, "create", &file);
    fixture(&program, "local", &file);
    let local = command(&program, &["get", ROOT]);
    assert_eq!(local["source_archive"]["kind"], "program");
    let before_count = list(&program).as_array().unwrap().len();
    let receipt = command(&program, &["import-gdt", file.to_str().unwrap(), "--all"]);
    assert_eq!(
        receipt["changed"], true,
        "Origin adoption is a saved change: {receipt}"
    );
    assert!(receipt["roots"]
        .as_array()
        .unwrap()
        .contains(&json!("/Other/Unselected")));
    assert_eq!(list(&program).as_array().unwrap().len(), before_count);
    reopen(&program);
    fixture(&program, "check-import", &file);
    let imported = command(&program, &["get", ROOT]);
    assert_eq!(imported["source_archive"]["kind"], "file");
    assert_ne!(imported["universal_id"], local["universal_id"]);
    restore_program();
}

#[test]
#[serial]
fn dependency_conflict_and_divergent_same_origin_fail_without_saved_changes() {
    require_ghidra!();
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("source.gdt");
    let program = create_type_edit_program("x86:LE:64:default");
    fixture(&program, "create", &file);
    fixture(&program, "conflict", &file);
    let before = list(&program);
    let conflicting = command(&program, &["get", "/Gdt/Payload"]);
    type_command(
        &program,
        &[
            "import-gdt",
            file.to_str().unwrap(),
            "--where",
            r#"path="/Gdt/Root""#,
        ],
    )
    .assert_failure()
    .assert_stderr_contains("conflict")
    .assert_stderr_contains("/Gdt/Payload");
    reopen(&program);
    assert_eq!(list(&program), before);
    assert_eq!(command(&program, &["get", "/Gdt/Payload"]), conflicting);

    let target = create_type_edit_program("x86:LE:64:default");
    command(
        &target,
        &[
            "import-gdt",
            file.to_str().unwrap(),
            "--where",
            r#"path="/Gdt/Root""#,
        ],
    );
    let before = list(&target);
    let before_definitions = definitions(&target);
    let source_before = candidates(Some(&file));
    fixture(&target, "diverge", &file);
    let source_after = candidates(Some(&file));
    for name in NAMES {
        let path = format!("/Gdt/{name}");
        let row = |value: &Value| {
            value["types"]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["path"] == path)
                .unwrap()
                .clone()
        };
        assert_eq!(
            row(&source_before)["universal_id"],
            row(&source_after)["universal_id"]
        );
    }
    type_command(
        &target,
        &[
            "import-gdt",
            file.to_str().unwrap(),
            "--where",
            r#"path="/Gdt/Root""#,
        ],
    )
    .assert_failure()
    .assert_stderr_contains("conflict")
    .assert_stderr_contains("/Gdt/Payload");
    reopen(&target);
    assert_eq!(list(&target), before);
    assert_eq!(definitions(&target), before_definitions);
    restore_program();
}

#[test]
#[serial]
fn different_file_origins_and_moved_identities_are_not_silently_reassociated() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    let directory = tempfile::tempdir().unwrap();
    let first = directory.path().join("first.gdt");
    let second = directory.path().join("second.gdt");
    fixture(&program, "create", &first);
    fixture(&program, "create", &second);
    command(&program, &["import-gdt", first.to_str().unwrap(), "--all"]);
    let before = definitions(&program);
    type_command(&program, &["import-gdt", second.to_str().unwrap(), "--all"])
        .assert_failure()
        .assert_stderr_contains("conflict");
    reopen(&program);
    assert_eq!(definitions(&program), before);
    fixture(&program, "check-import", &first);
    command(&program, &["category", "create", "/Moved"]);
    command(&program, &["move", ROOT, "--category", "/Moved"]);
    let before = list(&program);
    let moved = command(&program, &["get", "/Moved/Root"]);
    type_command(
        &program,
        &[
            "import-gdt",
            first.to_str().unwrap(),
            "--where",
            r#"path="/Gdt/Root""#,
        ],
    )
    .assert_failure()
    .assert_stderr_contains("conflict");
    reopen(&program);
    assert_eq!(list(&program), before);
    assert_eq!(command(&program, &["get", "/Moved/Root"]), moved);
    restore_program();
}

#[test]
#[serial]
fn incompatible_layout_endianness_and_scalar_semantics_are_rejected_before_import() {
    require_ghidra!();
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("x64.gdt");
    let source = create_type_edit_program("x86:LE:64:default");
    fixture(&source, "create", &file);
    let target = create_type_edit_program("x86:LE:32:default");
    let before = list(&target);
    type_command(
        &target,
        &[
            "import-gdt",
            file.to_str().unwrap(),
            "--where",
            r#"path="/Gdt/Node""#,
        ],
    )
    .assert_failure()
    .assert_stderr_contains("layout");
    reopen(&target);
    assert_eq!(list(&target), before);
    // Architecture metadata alone is not a conflict when the selected graph is ABI independent.
    command(
        &target,
        &[
            "import-gdt",
            file.to_str().unwrap(),
            "--where",
            r#"path="/Gdt/Payload""#,
        ],
    );
    assert_eq!(command(&target, &["get", "/Gdt/Payload"])["size"], 4);

    let big_endian = create_type_edit_program("PowerPC:BE:32:default");
    let before = list(&big_endian);
    type_command(
        &big_endian,
        &[
            "import-gdt",
            file.to_str().unwrap(),
            "--where",
            r#"path="/Gdt/Payload""#,
        ],
    )
    .assert_failure()
    .assert_stderr_contains("layout");
    reopen(&big_endian);
    assert_eq!(list(&big_endian), before);

    let chars = directory.path().join("signed-char.gdt");
    fixture(&source, "create-char", &chars);
    // This supported language uses unsigned plain char; the source x86 ABI uses signed char.
    let unsigned_char = create_type_edit_program("Hexagon:LE:32:default");
    let before = list(&unsigned_char);
    type_command(
        &unsigned_char,
        &[
            "import-gdt",
            chars.to_str().unwrap(),
            "--where",
            r#"path="/Gdt/Character""#,
        ],
    )
    .assert_failure()
    .assert_stderr_contains("layout");
    reopen(&unsigned_char);
    assert_eq!(list(&unsigned_char), before);
    restore_program();
}

#[test]
#[serial]
fn local_export_owns_fresh_archive_identities_and_preserves_the_saved_program() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("local export.gdt");
    fixture(&program, "local", &file);
    let before = definitions(&program);
    let source_before = candidates(None)["source"].clone();
    command(
        &program,
        &[
            "export-gdt",
            file.to_str().unwrap(),
            "--where",
            r#"path="/Gdt/Root""#,
        ],
    );
    assert_eq!(candidates(None)["source"], source_before);
    assert_eq!(definitions(&program), before);
    fixture(&program, "check-export", &file);
    reopen(&program);
    assert_eq!(definitions(&program), before);
    let bytes = std::fs::read(&file).unwrap();
    type_command(&program, &["export-gdt", file.to_str().unwrap(), "--all"])
        .assert_failure()
        .assert_stderr_contains("exists");
    assert_eq!(std::fs::read(&file).unwrap(), bytes);
    assert_eq!(definitions(&program), before);
    let target = create_type_edit_program("x86:LE:64:default");
    command(&target, &["import-gdt", file.to_str().unwrap(), "--all"]);
    reopen(&target);
    fixture(&target, "check-import", &file);
    restore_program();
}

#[test]
#[serial]
fn selection_guards_reject_missing_paths_and_changed_sources_without_mutation() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("source.gdt");
    let output = directory.path().join("guarded.gdt");
    fixture(&program, "create", &file);
    let snapshot = candidates(Some(&file));
    let before = list(&program);
    let client = harness().client().unwrap();
    let missing = client.send_command(
        "type_import_gdt",
        Some(json!({
            "file": file, "paths": ["/Gdt/Missing"], "source": snapshot["source"]
        })),
    );
    assert!(missing.is_err());
    assert_eq!(list(&program), before);
    fixture(&program, "diverge", &file);
    let stale = client
        .send_command(
            "type_import_gdt",
            Some(json!({
                "file": file, "paths": [ROOT], "source": snapshot["source"]
            })),
        )
        .unwrap_err();
    assert!(stale.to_string().contains("changed"), "{stale:#}");
    reopen(&program);
    assert_eq!(list(&program), before);

    command(&program, &["import-gdt", file.to_str().unwrap(), "--all"]);
    let snapshot = candidates(None);
    command(&program, &["create", "struct", "AfterSelection"]);
    let before = list(&program);
    let stale = client
        .send_command(
            "type_export_gdt",
            Some(json!({
                "file": output, "paths": [ROOT], "source": snapshot["source"]
            })),
        )
        .unwrap_err();
    assert!(stale.to_string().contains("changed"), "{stale:#}");
    assert!(!output.exists());
    reopen(&program);
    assert_eq!(list(&program), before);
    restore_program();
}

#[test]
#[serial]
fn invalid_sources_and_empty_selections_leave_no_types_or_archive() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("source.gdt");
    let invalid = directory.path().join("invalid.gdt");
    let missing = directory.path().join("missing.gdt");
    let output = directory.path().join("empty.gdt");
    fixture(&program, "create", &file);
    std::fs::write(&invalid, b"This is not a native Ghidra type archive.").unwrap();
    let before = list(&program);
    for source in [&invalid, &missing] {
        type_command(&program, &["import-gdt", source.to_str().unwrap(), "--all"]).assert_failure();
    }
    type_command(
        &program,
        &[
            "import-gdt",
            file.to_str().unwrap(),
            "--where",
            r#"path="/absent/Type""#,
        ],
    )
    .assert_failure();
    type_command(
        &program,
        &[
            "export-gdt",
            output.to_str().unwrap(),
            "--where",
            r#"path="/absent/Type""#,
        ],
    )
    .assert_failure();
    assert!(!output.exists());
    reopen(&program);
    assert_eq!(list(&program), before);
    restore_program();
}

#[test]
#[serial]
fn replacing_archive_bytes_with_the_same_mtime_does_not_reuse_cached_definitions() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("source.gdt");
    let replacement = directory.path().join("replacement.gdt");
    fixture(&program, "create", &file);
    fixture(&program, "create", &replacement);
    fixture(&program, "diverge", &replacement);
    let snapshot = candidates(Some(&file));
    let incoming = candidates(Some(&replacement));
    let original_mtime = std::fs::metadata(&file).unwrap().modified().unwrap();
    std::fs::copy(&replacement, &file).unwrap();
    std::fs::File::options()
        .write(true)
        .open(&file)
        .unwrap()
        .set_modified(original_mtime)
        .unwrap();
    let fresh = candidates(Some(&file));
    assert_eq!(
        fresh["source"]["archive_id"],
        incoming["source"]["archive_id"]
    );
    assert_ne!(
        fresh["source"]["archive_id"],
        snapshot["source"]["archive_id"]
    );
    let identities = |value: &Value| {
        value["types"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| {
                json!([
                    row["path"],
                    row["universal_id"],
                    row["source_archive"]["id"]
                ])
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(identities(&fresh), identities(&incoming));
    let client = harness().client().unwrap();
    let stale = client
        .send_command(
            "type_import_gdt",
            Some(json!({"file": file, "paths": [ROOT], "source": snapshot["source"]})),
        )
        .unwrap_err();
    assert!(stale.to_string().contains("changed"), "{stale:#}");
    command(
        &program,
        &[
            "import-gdt",
            file.to_str().unwrap(),
            "--where",
            r#"path="/Gdt/Payload""#,
        ],
    );
    reopen(&program);
    let payload = command(&program, &["get", "/Gdt/Payload"]);
    assert_eq!(payload["components"][0]["name"], "divergent");
    assert_eq!(payload["components"][0]["type"], "float");
    restore_program();
}

#[test]
#[serial]
fn unrepresentable_component_endianness_is_rejected_without_publishing() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("settings.gdt");
    fixture(&program, "local", &file);
    fixture(&program, "semantic-setting", &file);
    let before = definitions(&program);
    let source_before = candidates(None)["source"].clone();
    type_command(
        &program,
        &[
            "export-gdt",
            file.to_str().unwrap(),
            "--where",
            r#"path="/Gdt/Root""#,
        ],
    )
    .assert_failure()
    .assert_stderr_contains("setting");
    assert!(!file.exists());
    assert_eq!(candidates(None)["source"], source_before);
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    reopen(&program);
    assert_eq!(definitions(&program), before);
    restore_program();
}

#[test]
#[serial]
fn cancellation_and_presave_failures_preserve_databases_and_unpublished_archives() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source.gdt");
    fixture(&program, "create", &source);
    let source_bytes = std::fs::read(&source).unwrap();
    let client = harness().client().unwrap();
    for mode in ["cancel-import", "cancel-export", "pending-save"] {
        client.open_program(&program).unwrap();
        let output = directory.path().join(format!("{mode}.gdt"));
        let folder = format!("gdt-probe-{}", uuid::Uuid::new_v4());
        let result = client
            .script_run_source(
                include_str!("GdtArchiveProbe.java"),
                &[
                    mode.into(),
                    source.to_string_lossy().into_owned(),
                    output.to_string_lossy().into_owned(),
                    folder.clone(),
                ],
                &[],
                false,
            )
            .unwrap();
        assert!(
            result["stdout"]
                .as_str()
                .unwrap()
                .contains(&format!("gdt-probe-ok:{mode}")),
            "{result}"
        );
        let copied = format!("/{folder}/{program}");
        reopen(&copied);
        let expected = if mode == "pending-save" {
            "/GdtProbePending"
        } else {
            ROOT
        };
        command(&copied, &["get", expected]);
        if mode != "cancel-import" {
            assert!(output.is_file());
        }
    }
    assert_eq!(std::fs::read(&source).unwrap(), source_bytes);
    restore_program();
}
