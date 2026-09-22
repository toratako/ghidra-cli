use super::{echo_args_script_path, harness, test_project, TEST_PROGRAM};
use serial_test::serial;
use std::fs;

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
    let value: serde_json::Value = crate::json_output::from_slice(&output.stdout).unwrap();
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
    let result: serde_json::Value = crate::json_output::from_slice(&output.stdout).unwrap();
    // Java println uses the host line separator; compare LF and CRLF alike.
    assert_eq!(
        result["stdout"].as_str().unwrap().replace("\r\n", "\n"),
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
        result["stdout"].as_str().unwrap().replace("\r\n", "\n"),
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
    let result: serde_json::Value = crate::json_output::from_slice(&output.stdout).unwrap();
    assert_eq!(
        result["stdout"].as_str().unwrap().replace("\r\n", "\n"),
        "audit.packaged.PackagedAudit:stdin:stdin arg\n"
    );
    assert_eq!(result["script"], "PackagedAudit.java");
    assert!(!std::path::Path::new(result["path"].as_str().unwrap()).exists());
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
