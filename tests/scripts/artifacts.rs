use super::{harness, stage_script, test_project, TEST_PROGRAM};
use serial_test::serial;
use std::{fs, path::PathBuf};

fn write_artifact_script_path() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("fixtures");
    path.push("scripts");
    path.push("WriteArtifact.java");
    path
}

/// Phase 4.2: a declared JSONL artifact is validated and a manifest (row count,
/// checksum, binary provenance) is attached; a missing declared artifact fails
/// the job closed. Absolute paths are used for both the script's output arg and
/// `--expect` so the bridge validates exactly the file the script wrote.
#[test]
#[serial]
fn test_script_run_artifact_contract() {
    require_ghidra!();
    let _harness = harness();

    let fixture = write_artifact_script_path();
    assert!(fixture.exists(), "fixture missing: {}", fixture.display());
    let script = stage_script(&fixture);

    let out =
        std::env::temp_dir().join(format!("ghidra_cli_artifact_{}.jsonl", std::process::id()));
    let out_str = out.to_str().unwrap();
    let _ = fs::remove_file(&out);

    // Success: script writes 5 rows, we require >= 3.
    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("script")
        .arg("run")
        .arg(script.to_str().unwrap())
        .arg("--project")
        .arg(test_project())
        .arg("--program")
        .arg(TEST_PROGRAM)
        .arg("--expect-rows")
        .arg(out_str)
        .arg("3")
        .arg("--")
        .arg(out_str)
        .arg("5")
        .output()
        .expect("Failed to run command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "expected success.\nstdout: {}\nstderr: {}",
        stdout,
        stderr
    );
    assert!(
        stdout.contains("artifacts") && stdout.contains("\"rows\""),
        "expected artifact manifest with row count, got: {}",
        stdout
    );
    assert!(
        stdout.contains("wrote 5 records"),
        "expected captured script stdout, got: {}",
        stdout
    );
    let _ = fs::remove_file(&out);

    // Failure: declare an artifact the script never writes -> job fails closed.
    let missing =
        std::env::temp_dir().join(format!("ghidra_cli_missing_{}.jsonl", std::process::id()));
    let out2 =
        std::env::temp_dir().join(format!("ghidra_cli_artifact2_{}.jsonl", std::process::id()));
    let output2 = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("script")
        .arg("run")
        .arg(script.to_str().unwrap())
        .arg("--project")
        .arg(test_project())
        .arg("--program")
        .arg(TEST_PROGRAM)
        .arg("--expect")
        .arg(missing.to_str().unwrap())
        .arg("--")
        .arg(out2.to_str().unwrap())
        .arg("5")
        .output()
        .expect("Failed to run command");

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output2.stdout),
        String::from_utf8_lossy(&output2.stderr)
    );
    assert!(
        !output2.status.success(),
        "expected failure for a missing declared artifact, got success: {}",
        combined
    );
    assert!(
        combined.contains("validation failed") || combined.contains("missing"),
        "expected artifact-validation error, got: {}",
        combined
    );
    let _ = fs::remove_file(&out2);
}

/// Failures retain script output, artifact diagnostics, and the request's save outcome.
#[test]
#[serial]
fn test_script_failure_diagnostics() {
    require_ghidra!();
    let client = harness().client().unwrap();
    let marker = format!("diagnostics-{}", uuid::Uuid::new_v4());
    let error = client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
public class FailWithOutput extends GhidraScript {
    public void run() throws Exception {
        currentProgram.getOptions("DiagnosticTest").setString("marker", getScriptArgs()[0]);
        println("before failure");
        throw new IllegalStateException("intentional diagnostic failure");
    }
}
"#,
            &[marker],
            &[],
            false,
        )
        .unwrap_err();
    let detail = &error
        .downcast_ref::<ghidra_cli::ipc::protocol::BridgeCommandError>()
        .unwrap()
        .detail;
    assert!(detail["stdout"]
        .as_str()
        .unwrap()
        .contains("before failure"));
    assert_eq!(detail["partial_changes_saved"], true);

    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("missing.jsonl");
    let error = client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
public class MissingArtifactOutput extends GhidraScript {
    public void run() { println("artifact diagnostic output"); }
}
"#,
            &[],
            &[serde_json::json!({"path":missing})],
            false,
        )
        .unwrap_err();
    let detail = &error
        .downcast_ref::<ghidra_cli::ipc::protocol::BridgeCommandError>()
        .unwrap()
        .detail;
    assert!(detail["stdout"]
        .as_str()
        .unwrap()
        .contains("artifact diagnostic output"));
    assert_eq!(detail["artifacts"][0]["exists"], false);
    assert_eq!(detail["artifacts"][0]["path"], missing.to_str().unwrap());
}

/// /proc/self/mem is a regular file whose unmapped offset zero fails on read,
/// including for root. allow_empty must not turn that checksum failure into success.
#[cfg(target_os = "linux")]
#[test]
#[serial]
fn test_artifact_checksum_read_failure_fails_validation() {
    require_ghidra!();
    let client = harness().client().unwrap();
    let error = client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
public class UnreadableArtifact extends GhidraScript {
    public void run() { println("checksum read diagnostic"); }
}
"#,
            &[],
            &[serde_json::json!({"path": "/proc/self/mem"})],
            true,
        )
        .unwrap_err();
    assert!(error.to_string().contains("Artifact validation failed"));
    let detail = &error
        .downcast_ref::<ghidra_cli::ipc::protocol::BridgeCommandError>()
        .unwrap()
        .detail;
    assert_eq!(detail["artifacts"][0]["exists"], true);
    assert!(detail["artifacts"][0]["manifest_error"].is_string());
    assert!(detail["artifacts"][0]["sha256"].is_null());
    assert!(detail["stdout"]
        .as_str()
        .unwrap()
        .contains("checksum read diagnostic"));
}

#[test]
#[serial]
fn test_artifact_row_bounds_are_checked_before_script_execution() {
    require_ghidra!();
    let client = harness().client().unwrap();
    let work = tempfile::tempdir().unwrap();
    let artifact = work.path().join("rows.jsonl");
    let source = r#"
import ghidra.app.script.GhidraScript;
import java.nio.file.Files;
import java.nio.file.Path;
public class WriteOneArtifactRow extends GhidraScript {
    public void run() throws Exception {
        Files.writeString(Path.of(getScriptArgs()[0]), "{}\n");
    }
}
"#;
    let args = [artifact.to_str().unwrap().to_owned()];
    for minimum in [
        serde_json::json!(9223372036854775808_u64),
        serde_json::json!(u64::MAX),
        serde_json::json!(-1),
        serde_json::json!(0.5),
        serde_json::json!("12"),
        serde_json::json!(true),
    ] {
        let error = client
            .script_run_source(
                source,
                &args,
                &[serde_json::json!({"path": artifact, "min_rows": minimum})],
                false,
            )
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("min_rows must be an integer from 0 to 9223372036854775807"),
            "{error}"
        );
        assert!(
            !artifact.exists(),
            "Script executed with invalid minimum {minimum}"
        );
    }
    for minimum in [0, 1] {
        let result = client
            .script_run_source(
                source,
                &args,
                &[serde_json::json!({"path": artifact, "min_rows": minimum})],
                false,
            )
            .unwrap();
        assert_eq!(result["artifacts"][0]["rows"], 1);
    }
    let error = client
        .script_run_source(
            source,
            &args,
            &[serde_json::json!({"path": artifact, "min_rows": i64::MAX})],
            false,
        )
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("1 rows, expected >= 9223372036854775807"),
        "{error}"
    );
}

#[test]
#[serial]
fn test_script_assertion_reports_saved_edit_and_bridge_remains_usable() {
    require_ghidra!();
    let client = harness().client().unwrap();
    let marker = format!("assertion-{}", uuid::Uuid::new_v4());
    let error = client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
public class FailWithAssertion extends GhidraScript {
    public void run() {
        currentProgram.getOptions("DiagnosticTest").setString("assertion_marker", getScriptArgs()[0]);
        println("before assertion");
        throw new AssertionError("intentional script assertion");
    }
}
"#,
            &[marker.clone()],
            &[],
            false,
        )
        .unwrap_err();
    assert!(
        error.to_string().contains("intentional script assertion"),
        "{error}"
    );
    let detail = &error
        .downcast_ref::<ghidra_cli::ipc::protocol::BridgeCommandError>()
        .unwrap()
        .detail;
    assert!(detail["stdout"]
        .as_str()
        .unwrap()
        .contains("before assertion"));
    assert_eq!(detail["partial_changes_saved"], true);
    assert!(client.ping().unwrap());
    client.program_close().unwrap();
    client.open_program(TEST_PROGRAM).unwrap();
    let result = client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
public class ReadAssertionMarker extends GhidraScript {
    public void run() {
        println(currentProgram.getOptions("DiagnosticTest").getString("assertion_marker", "missing"));
    }
}
"#,
            &[],
            &[],
            false,
        )
        .unwrap();
    assert!(
        result["stdout"].as_str().unwrap().contains(&marker),
        "{result}"
    );
}

#[test]
#[serial]
fn test_malformed_artifact_expectations_fail_before_script_execution() {
    require_ghidra!();
    let client = harness().client().unwrap();
    let work = tempfile::tempdir().unwrap();
    let artifact = work.path().join("unexpected.txt");
    let source = r#"
import ghidra.app.script.GhidraScript;
import java.nio.file.Files;
import java.nio.file.Path;
public class WriteOnRun extends GhidraScript {
    public void run() throws Exception {
        Files.writeString(Path.of(getScriptArgs()[0]), "ran");
    }
}
"#;
    for (expect, message) in [
        (serde_json::json!(null), "expect must be an array"),
        (
            serde_json::json!({"path": artifact}),
            "expect must be an array",
        ),
        (serde_json::json!([null]), "expect[0] must be an object"),
        (
            serde_json::json!([{}]),
            "expect[0].path must be a nonempty string",
        ),
        (
            serde_json::json!([{"path": 42}]),
            "expect[0].path must be a nonempty string",
        ),
        (
            serde_json::json!([{"path": artifact, "schema": 42}]),
            "expect[0].schema must be a string",
        ),
    ] {
        let error = client
            .send_command(
                "script_run",
                Some(serde_json::json!({
                    "source": source,
                    "args": [artifact.to_str().unwrap()],
                    "expect": expect,
                })),
            )
            .unwrap_err();
        assert!(error.to_string().contains(message), "{error}");
        assert!(
            !artifact.exists(),
            "script ran with malformed expect: {expect}"
        );
    }
}
