use super::*;

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
