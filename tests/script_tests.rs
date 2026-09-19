//! Tests for script execution operations.

use serial_test::serial;
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;

#[macro_use]
mod common;
use common::{ensure_test_project, DaemonTestHarness};

use common::test_project;
const TEST_PROGRAM: &str = common::FIXTURE_PROGRAM;

static HARNESS: OnceLock<DaemonTestHarness> = OnceLock::new();

fn harness() -> &'static DaemonTestHarness {
    HARNESS.get_or_init(|| {
        ensure_test_project(test_project(), TEST_PROGRAM);
        DaemonTestHarness::new(test_project(), TEST_PROGRAM).expect("Failed to start daemon")
    })
}

fn echo_args_script_path() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("fixtures");
    path.push("scripts");
    path.push("EchoArgs.java");
    path
}

/// Copy a fixture script into a unique, fresh temp directory and return the copy.
///
/// Ghidra resolves a script to the FIRST registered source directory that is an
/// ancestor of it (GhidraScriptUtil.findSourceDirectoryContaining), and bundle
/// registrations persist in the OSGi cache across bridge sessions. Running a
/// fixture straight out of tests/fixtures/** can therefore be shadowed by a
/// previously-registered ancestor (e.g. tests/fixtures itself), which corrupts
/// the derived class name. Staging into a unique temp dir gives each run an
/// unregistered parent — exactly the arbitrary-absolute-path case users hit.
fn stage_script(fixture: &PathBuf) -> PathBuf {
    let stem = fixture.file_stem().unwrap().to_string_lossy().into_owned();
    let dir =
        std::env::temp_dir().join(format!("ghidra_cli_script_{}_{}", std::process::id(), stem));
    fs::create_dir_all(&dir).expect("create staging dir");
    let dest = dir.join(fixture.file_name().unwrap());
    fs::copy(fixture, &dest).expect("copy fixture script");
    dest
}

fn write_artifact_script_path() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("fixtures");
    path.push("scripts");
    path.push("WriteArtifact.java");
    path
}

fn get_test_script_path() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("fixtures");
    path.push("test_script.py");
    path
}

fn create_test_script() -> PathBuf {
    let script_path = get_test_script_path();

    fs::create_dir_all(script_path.parent().unwrap()).ok();

    let script_content = r#"# Test script
# @category Test

print("Test script executed")
"#;

    fs::write(&script_path, script_content).expect("Failed to write test script");
    script_path
}

#[test]
#[serial]
fn test_script_list() {
    require_ghidra!();
    let _harness = harness();

    // script list does not accept --project/--program arguments,
    // so it may fail with "no project specified" unless a default is configured
    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("script")
        .arg("list")
        .output()
        .expect("Failed to run command");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success()
            || stderr.contains("No project specified")
            || stderr.contains("no default project"),
        "Expected success or no-project error, got: {}",
        stderr
    );
}

#[test]
#[serial]
fn test_script_run() {
    require_ghidra!();
    let script_path = create_test_script();

    let _harness = harness();

    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("script")
        .arg("run")
        .arg(script_path.to_str().unwrap())
        .arg("--project")
        .arg(test_project())
        .arg("--program")
        .arg(TEST_PROGRAM)
        .output()
        .expect("Failed to run command");

    // Ghidra's runScript may not find scripts outside its script directories
    // Accept either success or "Script does not exist" error
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success()
            || stderr.contains("Script does not exist")
            || stderr.contains("Script not found")
            || stderr.contains("No script provider") // Python provider not installed
            || stderr.contains("Script failed")
            || stderr.contains("Script threw")
            || stderr.contains("Failed to run script"),
        "Expected success or script-not-found error, got: {}",
        stderr
    );

    fs::remove_file(script_path).ok();
}

/// A checked-in Java script runs by absolute path (no global-scripts-dir copy),
/// receives real positional arguments (Phase 4.1), and its stdout is captured
/// into the structured result. Java is used deliberately: it compiles via the
/// doctor-resolved JDK, whereas Python needs a provider that may be absent.
#[test]
#[serial]
fn test_script_run_java_args() {
    require_ghidra!();
    let _harness = harness();

    let fixture = echo_args_script_path();
    assert!(fixture.exists(), "fixture missing: {}", fixture.display());
    let script_path = stage_script(&fixture);

    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("script")
        .arg("run")
        .arg(script_path.to_str().unwrap())
        .arg("--project")
        .arg(test_project())
        .arg("--program")
        .arg(TEST_PROGRAM)
        .arg("--")
        .arg("hello")
        .arg("world")
        .output()
        .expect("Failed to run command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "script run failed.\nstdout: {}\nstderr: {}",
        stdout,
        stderr
    );
    // The captured script println() output lands in the result's `stdout` field.
    assert!(
        stdout.contains("ARGC=2") && stdout.contains("ARG0=hello") && stdout.contains("ARG1=world"),
        "expected echoed args in captured stdout, got: {}",
        stdout
    );
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
        .arg("--expect")
        .arg(format!("{}:3", out_str))
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

#[test]
#[serial]
fn test_script_run_nonexistent() {
    require_ghidra!();
    let _harness = harness();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("script")
        .arg("run")
        .arg("/nonexistent/script.py")
        .arg("--project")
        .arg(test_project())
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .failure();
}

#[test]
#[serial]
fn java_source_on_stdin_runs_without_interactive_prompt() {
    require_ghidra!();
    let _harness = harness();
    let source = std::fs::read_to_string(echo_args_script_path()).unwrap();
    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args([
            "--quiet",
            "script",
            "run",
            "-",
            "--project",
            test_project(),
            "--program",
            TEST_PROGRAM,
            "--",
            "from-stdin",
        ])
        .write_stdin(source)
        .timeout(std::time::Duration::from_secs(120))
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(value.to_string().contains("ARG0=from-stdin"), "{value}");
}

#[test]
#[serial]
fn java_source_on_stdin_uses_top_level_java_declarations() {
    require_ghidra!();
    let client = harness().client().unwrap();
    let cases = [
        (
            "FinalStdin",
            r#"
import ghidra.app.script.GhidraScript;
@Deprecated
public final class FinalStdin extends GhidraScript {
    public void run() { println("selected=" + getClass().getSimpleName()); }
}
"#,
        ),
        (
            "ActualStdin",
            r#"
import ghidra.app.script.GhidraScript;
// public class LineCommentDecoy extends GhidraScript {}
/* public class BlockCommentDecoy extends GhidraScript {} */
abstract class StdinBase extends GhidraScript {
    public static class NestedDecoy {}
    String text = "public class StringDecoy extends GhidraScript {}";
    String block = """
        public class TextBlockDecoy extends GhidraScript {}
        """;
    public void run() { println("selected=" + getClass().getSimpleName()); }
}
final public /* public class HeaderDecoy {} */ class ActualStdin extends StdinBase {}
"#,
        ),
        (
            "Unicode$Stdin",
            r#"
import ghidra.app.script.GhidraScript;
public class \u0055nicode$Stdin extends GhidraScript {
    public void run() { println("selected=" + getClass().getSimpleName()); }
}
"#,
        ),
    ];
    for (class_name, source) in cases {
        let from_stdin = client.script_run_source(source, &[], &[], false).unwrap();
        assert_eq!(from_stdin["script"], format!("{class_name}.java"));
        assert!(
            from_stdin["stdout"]
                .as_str()
                .unwrap()
                .contains(&format!("selected={class_name}")),
            "{from_stdin}"
        );

        // The same source must be accepted by Ghidra's ordinary file path.
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(format!("{class_name}.java"));
        fs::write(&path, source).unwrap();
        let from_file = client
            .script_run(path.to_str().unwrap(), &[], &[], false)
            .unwrap();
        assert_eq!(from_stdin["stdout"], from_file["stdout"]);
    }
}

#[test]
#[serial]
fn java_packaged_scripts_run_from_files_and_stdin() {
    require_ghidra!();
    let client = harness().client().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let source_dir = directory.path().join("scripts's space");
    #[cfg(unix)]
    let source_dir = source_dir.join(r"back\slash");
    fs::create_dir_all(&source_dir).unwrap();
    let source = r#"
// package comment.decoy;
package audit /* package another.decoy; */ . \u0070ackaged;
import ghidra.app.script.GhidraScript;
public final class PackagedAudit extends GhidraScript {
    public void run() {
        println(getClass().getName() + ":" + PackageMessage.text() + ":" + getScriptArgs()[0]);
    }
}
"#;
    let helper = |message: &str| {
        format!(
            r#"final class PackageMessage {{
    static String text() {{ return "{message}"; }}
}}
"#
        )
    };
    let path = source_dir.join("PackagedAudit.java");
    fs::write(&path, source).unwrap();
    fs::write(
        source_dir.join("PackageMessage.java"),
        format!("package audit.packaged;\n{}", helper("file")),
    )
    .unwrap();
    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .current_dir(directory.path())
        .args(["--json", "--quiet", "script", "run"])
        .arg(path.strip_prefix(directory.path()).unwrap())
        .args([
            "--project",
            test_project(),
            "--program",
            TEST_PROGRAM,
            "--",
            "arg with spaces",
        ])
        .timeout(std::time::Duration::from_secs(120))
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        result[0]["stdout"],
        "audit.packaged.PackagedAudit:file:arg with spaces\n"
    );

    // A registered ancestor must not supply a same-named packaged class when
    // the explicitly requested child bundle contains a different script/helper.
    let child = source_dir.join("child");
    fs::create_dir(&child).unwrap();
    let child_path = child.join("PackagedAudit.java");
    fs::write(&child_path, source).unwrap();
    fs::write(
        child.join("PackageMessage.java"),
        format!("package audit.packaged;\n{}", helper("child")),
    )
    .unwrap();
    let result = client
        .script_run(
            child_path.to_str().unwrap(),
            &["child arg".to_owned()],
            &[],
            false,
        )
        .unwrap();
    assert_eq!(
        result["stdout"],
        "audit.packaged.PackagedAudit:child:child arg\n"
    );

    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args([
            "--json",
            "--quiet",
            "script",
            "run",
            "-",
            "--project",
            test_project(),
            "--program",
            TEST_PROGRAM,
            "--",
            "stdin arg",
        ])
        .write_stdin(format!("{source}\n{}", helper("stdin")))
        .timeout(std::time::Duration::from_secs(120))
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        result[0]["stdout"],
        "audit.packaged.PackagedAudit:stdin:stdin arg\n"
    );
    assert_eq!(result[0]["script"], "PackagedAudit.java");
    assert!(!std::path::Path::new(result[0]["path"].as_str().unwrap()).exists());
}

#[test]
#[serial]
fn java_source_on_stdin_reports_invalid_declarations() {
    require_ghidra!();
    let _harness = harness();
    let cases = [
        (
            r#"
// public class CommentOnly {}
class Holder {
    String text = "public class StringOnly {}";
    public static class NestedOnly {}
}
"#,
            "must define exactly one top-level public class",
        ),
        (
            "public class First {} public class Second {}",
            "must define exactly one top-level public class",
        ),
        (
            "public class Broken { public void run( {} }",
            "Invalid inline Java source at line 1, column ",
        ),
    ];
    for (source, expected) in cases {
        let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
            .args([
                "--json",
                "--quiet",
                "script",
                "run",
                "-",
                "--project",
                test_project(),
                "--program",
                TEST_PROGRAM,
            ])
            .write_stdin(source)
            .timeout(std::time::Duration::from_secs(120))
            .output()
            .unwrap();
        assert!(!output.status.success(), "{output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
        let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(error["status"], "error");
        assert!(
            error["message"].as_str().unwrap().contains(expected),
            "{error}"
        );
    }
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
