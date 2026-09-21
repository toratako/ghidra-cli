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
        let value: serde_json::Value = result.json();
        assert_eq!(value[0]["components"][0]["name"], "value");
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
fn type_import_parse_failure_restores_types_and_applied_data_after_reopen() {
    require_ghidra!();
    let program = create_type_edit_program("x86:LE:64:default");
    type_command(
        &program,
        &["import-c", "struct Existing { int value; int tail; };"],
    )
    .assert_success();
    let client = harness().client().unwrap();
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.program.model.data.EndianSettingsDefinition;
import ghidra.program.model.data.Structure;
public class ApplyImportRollbackFixture extends GhidraScript {
    public void run() throws Exception {
        var structure = (Structure) currentProgram.getDataTypeManager().getDataType("/Existing");
        var component = structure.getComponent(0);
        component.setComment("saved field comment");
        FormatSettingsDefinition.DEF.setChoice(component.getDefaultSettings(), FormatSettingsDefinition.DECIMAL);
        EndianSettingsDefinition.DEF.setChoice(component.getDefaultSettings(), EndianSettingsDefinition.BIG);
        var address = toAddr(0x1000);
        currentProgram.getMemory().createInitializedBlock("data", address, 32, (byte) 0, monitor, false);
        var data = currentProgram.getListing().createData(address, structure);
        FormatSettingsDefinition.DEF.setChoice(data.getComponent(0), FormatSettingsDefinition.BINARY);
        EndianSettingsDefinition.DEF.setChoice(data.getComponent(0), EndianSettingsDefinition.LITTLE);
    }
}
"#,
            &[],
            &[],
            false,
        )
        .unwrap();
    let before = type_command(&program, &["list", "--limit", "0"]);
    before.assert_success();
    let before: serde_json::Value = before.json();

    // Both syntax and lexical failures follow a valid prefix that replaces
    // Existing. The parser commits its nested transaction even on failure, so
    // only the request boundary can restore all changes. The unterminated
    // comment throws TokenMgrError rather than an Exception.
    for invalid_suffix in ["struct Broken { int value[; };", "/* unterminated comment"] {
        let code = format!(
            "struct Existing {{ long long changed; }}; struct Fresh {{ int marker; }}; {invalid_suffix}"
        );
        let failed = type_command(&program, &["import-c", &code]);
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
            assert_eq!(after.json::<serde_json::Value>(), before);
            client
                .script_run_source(
                r#"
import ghidra.app.script.GhidraScript;
import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.program.model.data.EndianSettingsDefinition;
import ghidra.program.model.data.Structure;
public class CheckImportRollbackFixture extends GhidraScript {
    public void run() throws Exception {
        var structure = (Structure) currentProgram.getDataTypeManager().getDataType("/Existing");
        if (structure.getLength() != 8 || structure.getNumComponents() != 2)
            throw new IllegalStateException("Existing structure layout changed");
        var component = structure.getComponent(0);
        if (!"value".equals(component.getFieldName()) || !"tail".equals(structure.getComponent(1).getFieldName())
                || !"saved field comment".equals(component.getComment()))
            throw new IllegalStateException("Existing structure metadata changed");
        if (FormatSettingsDefinition.DEF.getChoice(component.getDefaultSettings()) != FormatSettingsDefinition.DECIMAL
                || EndianSettingsDefinition.DEF.getChoice(component.getDefaultSettings()) != EndianSettingsDefinition.BIG)
            throw new IllegalStateException("Existing field settings changed");
        var data = currentProgram.getListing().getDefinedDataAt(toAddr(0x1000));
        if (data == null || data.getLength() != 8 || !data.getDataType().equals(structure)
                || !"value".equals(data.getComponent(0).getFieldName()))
            throw new IllegalStateException("Applied structure data changed");
        if (FormatSettingsDefinition.DEF.getChoice(data.getComponent(0)) != FormatSettingsDefinition.BINARY
                || EndianSettingsDefinition.DEF.getChoice(data.getComponent(0)) != EndianSettingsDefinition.LITTLE)
            throw new IllegalStateException("Applied field settings changed");
    }
}
"#,
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
        .arg(&def_a)
        .with_project(test_project(), TEST_PROGRAM)
        .run()
        .assert_success();

    ghidra(harness)
        .arg("type")
        .arg("import-c")
        .arg("--category")
        .arg(&category_b)
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
    let listed_types: Vec<serde_json::Value> = list_result.json();

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
