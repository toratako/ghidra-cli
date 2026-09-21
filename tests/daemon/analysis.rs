use super::{start_daemon, TEST_PROGRAM};
use crate::common::{ensure_test_project, test_project};
use serde_json::{json, Value};
use serial_test::serial;

#[test]
#[serial]
fn analysis_options_preserve_types_validate_before_mutation_and_save() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().unwrap();
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.OptionType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
public class RegisterAnalysisTestOptions extends GhidraScript {
    public void run() {
        var options = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
        options.registerOption("CLI Test.Boolean", true, null, "A nested boolean setting");
        options.registerOption("CLI Test.Int", 7, null, "An integer setting");
        options.registerOption("CLI Test.Long", 8L, null, "A long setting");
        options.registerOption("CLI Test.Float", 0.5f, null, "A float setting");
        options.registerOption("CLI Test.Double", 0.25d, null, "A double setting");
        options.registerOption("CLI Test.String", "original", null, "A string setting");
        options.registerOption("CLI Test.Enum", SourceType.DEFAULT, null, "An enum setting");
        options.registerOption("CLI Test.File", OptionType.FILE_TYPE, null, null, "A file setting");
        options.registerOption("CLI Test.Color", java.awt.Color.BLACK, null, "A UI setting");
    }
}
"#,
            &[],
            &[],
            false,
        )
        .unwrap();

    let listed = client.analysis_option_list().unwrap();
    let rows = listed["options"].as_array().unwrap();
    assert_eq!(listed["count"], rows.len());
    let switch = rows
        .iter()
        .find(|row| row["name"] == "ASCII Strings")
        .unwrap();
    assert_eq!(switch["type"], "boolean");
    assert_eq!(switch["settable"], true);
    let original = switch["value"].as_bool().unwrap();
    let choices = client.analysis_option_get("CLI Test.Enum").unwrap();
    assert!(choices["choices"]
        .as_array()
        .unwrap()
        .contains(&json!("USER_DEFINED")));
    let int = client.analysis_option_get("CLI Test.Int").unwrap();
    assert_eq!(int["default"], 7);
    assert_eq!(int["description"], "An integer setting");
    let file = client.analysis_option_get("CLI Test.File").unwrap();
    assert_eq!(file["type"], "file");
    assert!(file["value"].is_null());
    assert_eq!(
        client.analysis_option_get("CLI Test.Color").unwrap()["settable"],
        false
    );

    // Exercise CLI enablement, then read the persisted Ghidra value through get.
    for enabled in [!original, original] {
        assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
            .args([
                "analysis",
                "option",
                "set",
                "ASCII Strings",
                if enabled { "true" } else { "false" },
            ])
            .args(["--project", test_project(), "--program", TEST_PROGRAM])
            .assert()
            .success();
        assert_eq!(
            client.analysis_option_get("ASCII Strings").unwrap()["value"],
            enabled
        );
    }

    let temp = tempfile::tempdir().unwrap();
    let file_path = temp
        .path()
        .join("symbols with spaces")
        .to_string_lossy()
        .into_owned();
    let cases: Vec<(&str, &str, &str, Value)> = vec![
        ("Boolean", "false", "boolean", json!(false)),
        ("Int", "-42", "int", json!(-42)),
        ("Long", "9223372036854775807", "long", json!(i64::MAX)),
        ("Float", "1.25", "float", json!(1.25)),
        ("Double", "1.125", "double", json!(1.125)),
        ("String", "", "string", json!("")),
        ("Enum", "USER_DEFINED", "enum", json!("USER_DEFINED")),
        ("File", &file_path, "file", json!(file_path)),
    ];
    for (suffix, value, kind, expected) in &cases {
        let name = format!("CLI Test.{suffix}");
        let changed = client.analysis_option_set(&name, value).unwrap();
        assert_eq!(changed["type"], *kind);
        assert_eq!(&changed["value"], expected);
        assert_eq!(changed["status"], "set");
        assert_eq!(
            &client.analysis_option_get(&name).unwrap()["value"],
            expected
        );
    }
    for (name, value) in [
        ("CLI Test.Boolean", json!("maybe")),
        ("CLI Test.Int", json!("2147483648")),
        ("CLI Test.Long", json!("9223372036854775808")),
        ("CLI Test.Float", json!("1e100")),
        ("CLI Test.Double", json!("NaN")),
        ("CLI Test.Enum", json!("unknown")),
        ("CLI Test.Color", json!("1")),
        ("CLI Test.File", json!("relative-symbols")),
        ("CLI Test.String", json!(123)),
    ] {
        let before = client.analysis_option_get(name).unwrap();
        let error = client
            .send_command(
                "analysis_option_set",
                Some(json!({"name": name, "value": value})),
            )
            .expect_err("invalid input must fail");
        let detail = error
            .downcast_ref::<ghidra_cli::ipc::protocol::BridgeCommandError>()
            .unwrap();
        assert_eq!(detail.detail["rolled_back"], true);
        assert_eq!(client.analysis_option_get(name).unwrap(), before);
    }
    assert!(client
        .analysis_option_set("CLI Test.Unknown", "true")
        .is_err());
    assert!(client.analysis_option_get("CLI Test.Unknown").is_err());

    // Verify actual native types in a separately opened saved database before closing.
    client.script_run_source(r#"
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
public class CheckSavedAnalysisOptions extends GhidraScript {
    public void run() throws Exception {
        Object consumer = new Object();
        Program saved = (Program) currentProgram.getDomainFile()
            .getReadOnlyDomainObject(consumer, DomainFile.DEFAULT_VERSION, monitor);
        try {
            var options = saved.getOptions(Program.ANALYSIS_PROPERTIES);
            if (options.getBoolean("CLI Test.Boolean", true)
                || options.getInt("CLI Test.Int", 0) != -42
                || options.getLong("CLI Test.Long", 0) != Long.MAX_VALUE
                || options.getFloat("CLI Test.Float", 0) != 1.25f
                || options.getDouble("CLI Test.Double", 0) != 1.125d
                || !options.getString("CLI Test.String", "bad").isEmpty()
                || options.getEnum("CLI Test.Enum", SourceType.DEFAULT) != SourceType.USER_DEFINED
                || !options.getFile("CLI Test.File", null).equals(new java.io.File(getScriptArgs()[0]))
                || options.contains("CLI Test.Unknown")) {
                throw new IllegalStateException("Saved analysis option values or types differ");
            }
        } finally { saved.release(consumer); }
    }
}
"#, std::slice::from_ref(&file_path), &[], false).unwrap();
    client.program_close().unwrap();
    client.open_program(TEST_PROGRAM).unwrap();
    for (suffix, _, kind, expected) in &cases {
        let actual = client
            .analysis_option_get(&format!("CLI Test.{suffix}"))
            .unwrap();
        assert_eq!(actual["type"], *kind);
        assert_eq!(&actual["value"], expected);
    }
    client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
public class RemoveAnalysisTestOptions extends GhidraScript {
    public void run() {
        var options = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
        for (String name : options.getOptionNames()) {
            if (name.startsWith("CLI Test.")) options.removeOption(name);
        }
    }
}
"#,
            &[],
            &[],
            false,
        )
        .unwrap();
}
