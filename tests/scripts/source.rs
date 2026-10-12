use super::{echo_args_script_path, harness, test_project, TEST_PROGRAM};
use serial_test::serial;
use std::fs;

fn inline_lifecycle(
    client: &ghidra_cli::ipc::client::BridgeClient,
    inspector: &std::path::Path,
) -> serde_json::Value {
    let result = client
        .script_run(inspector.to_str().unwrap(), &[], &[], false)
        .unwrap();
    let snapshot = result["stdout"]
        .as_str()
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("INLINE_LIFECYCLE="))
        .unwrap();
    serde_json::from_str(snapshot).unwrap()
}

#[test]
#[serial]
fn inline_script_bundles_are_released_on_success_failure_and_cancellation() {
    require_ghidra!();
    let client = harness().client().unwrap();
    let directory = tempfile::Builder::new()
        .prefix("inline lifetime's space ")
        .tempdir()
        .unwrap();
    let inspector = directory.path().join("InlineLifecycleInspector.java");
    fs::write(&inspector, include_str!("InlineLifecycleInspector.java")).unwrap();
    let before = inline_lifecycle(&client, &inspector);
    let source = include_str!("InlineLifetimeProbe.java");
    for round in 0..2 {
        for mode in ["success", "throw", "cancel", "compile_failure"] {
            let source = if mode == "compile_failure" {
                source.replace(
                    "println(\"inline lifetime \" + mode);",
                    "missingCompileSymbol();",
                )
            } else {
                source.to_owned()
            };
            let result = client.script_run_source(&source, &[mode.to_owned()], &[], false);
            if mode == "success" {
                let result = result.unwrap();
                assert!(result["stdout"]
                    .as_str()
                    .unwrap()
                    .contains("inline lifetime success"));
                assert!(!std::path::Path::new(result["path"].as_str().unwrap()).exists());
            } else {
                let error = result.unwrap_err();
                let expected = match mode {
                    "throw" => "lifetime probe failure",
                    "cancel" => "Script cancelled",
                    _ => "missingCompileSymbol",
                };
                assert!(error.to_string().contains(expected), "{error}");
                if mode == "compile_failure" {
                    let message = error.to_string();
                    assert!(
                        message.contains("The class could not be found"),
                        "{message}"
                    );
                    assert!(message.contains("cannot find symbol"), "{message}");
                }
            }
            assert_eq!(
                inline_lifecycle(&client, &inspector),
                before,
                "{round}: {mode}"
            );
        }
    }
    assert!(inspector.is_file(), "file-script source must be retained");
}

#[test]
#[serial]
fn inline_cleanup_failure_preserves_script_output_and_original_error() {
    require_ghidra!();
    let client = harness().client().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let inspector = directory.path().join("InlineLifecycleInspector.java");
    fs::write(&inspector, include_str!("InlineLifecycleInspector.java")).unwrap();
    let before = inline_lifecycle(&client, &inspector);
    for mode in ["leftover", "throw-leftover"] {
        let error = client
            .script_run_source(
                include_str!("InlineLifetimeProbe.java"),
                &[mode.to_owned()],
                &[],
                false,
            )
            .unwrap_err();
        assert!(
            error.to_string().contains("Inline script cleanup failed"),
            "{error}"
        );
        if mode == "throw-leftover" {
            assert!(
                error.to_string().contains("lifetime probe failure"),
                "{error}"
            );
        }
        let detail = &error
            .downcast_ref::<ghidra_cli::ipc::protocol::BridgeCommandError>()
            .unwrap()
            .detail;
        assert!(detail["stdout"]
            .as_str()
            .unwrap()
            .contains(&format!("inline lifetime {mode}")));
        let cleanup = &detail["cleanup_error"];
        assert_eq!(cleanup["stage"], "script.cleanup");
        let source_directory = std::path::Path::new(cleanup["source_directory"].as_str().unwrap());
        let compiled = std::path::Path::new(cleanup["compiled_directory"].as_str().unwrap());
        assert_eq!(
            cleanup["remaining_paths"],
            serde_json::json!([source_directory])
        );
        assert!(!compiled.exists(), "compiled bundle was retained");
        assert!(!source_directory.join("InlineLifetimeProbe.java").exists());
        let output = source_directory.join("preserved.txt");
        assert_eq!(fs::read_to_string(&output).unwrap(), "script-owned output");
        fs::remove_file(output).unwrap();
        fs::remove_dir(source_directory).unwrap();
        assert_eq!(inline_lifecycle(&client, &inspector), before);
    }
}

#[test]
#[serial]
fn inline_cleanup_preserves_replacement_bundle_ownership() {
    require_ghidra!();
    let client = harness().client().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let inspector = directory.path().join("InlineLifecycleInspector.java");
    fs::write(&inspector, include_str!("InlineLifecycleInspector.java")).unwrap();
    let recovery = directory.path().join("InlineLifetimeReplacement.java");
    let source = include_str!("InlineLifetimeReplacement.java");
    fs::write(&recovery, source).unwrap();
    let metadata = directory.path().join("replacement.json");
    let before = inline_lifecycle(&client, &inspector);
    for mode in ["registry", "location"] {
        let error = client
            .script_run_source(
                source,
                &[mode.to_owned(), metadata.to_string_lossy().into_owned()],
                &[],
                false,
            )
            .unwrap_err();
        assert!(error.to_string().contains("changed ownership"), "{error}");
        let detail = &error
            .downcast_ref::<ghidra_cli::ipc::protocol::BridgeCommandError>()
            .unwrap()
            .detail;
        assert_eq!(detail["cleanup_error"]["stage"], "script.cleanup");
        assert!(detail["stdout"]
            .as_str()
            .unwrap()
            .contains(&format!("replaced {mode}")));
        for operation in ["check", "cleanup"] {
            client
                .script_run(
                    recovery.to_str().unwrap(),
                    &[
                        operation.to_owned(),
                        metadata.to_string_lossy().into_owned(),
                    ],
                    &[],
                    false,
                )
                .unwrap();
        }
        assert_eq!(inline_lifecycle(&client, &inspector), before);
    }
}

#[test]
#[serial]
fn inline_registration_callback_failure_reports_unconfirmed_ownership() {
    require_ghidra!();
    let client = harness().client().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let inspector = directory.path().join("InlineLifecycleInspector.java");
    fs::write(&inspector, include_str!("InlineLifecycleInspector.java")).unwrap();
    let recovery = directory.path().join("InlineLifetimeReplacement.java");
    fs::write(&recovery, include_str!("InlineLifetimeReplacement.java")).unwrap();
    let metadata = directory.path().join("registration.json");
    let before = inline_lifecycle(&client, &inspector);
    client
        .script_run(
            recovery.to_str().unwrap(),
            &[
                "install-add-failure".to_owned(),
                metadata.to_string_lossy().into_owned(),
            ],
            &[],
            false,
        )
        .unwrap();
    let error = client
        .script_run_source(
            include_str!("InlineLifetimeProbe.java"),
            &["success".to_owned()],
            &[],
            false,
        )
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("ownership could not be confirmed"),
        "{error}"
    );
    assert!(
        error
            .to_string()
            .contains("inline registration listener failure"),
        "{error}"
    );
    let detail = &error
        .downcast_ref::<ghidra_cli::ipc::protocol::BridgeCommandError>()
        .unwrap()
        .detail;
    let info: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&metadata).unwrap()).unwrap();
    assert_eq!(detail["cleanup_error"]["stage"], "script.cleanup");
    assert_eq!(
        detail["cleanup_error"]["remaining_paths"],
        serde_json::json!([info["source_directory"]])
    );
    client
        .script_run(
            recovery.to_str().unwrap(),
            &[
                "cleanup-add-failure".to_owned(),
                metadata.to_string_lossy().into_owned(),
            ],
            &[],
            false,
        )
        .unwrap();
    assert_eq!(inline_lifecycle(&client, &inspector), before);
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
