//! Regression tests for fixture generation and fail-closed test prerequisites.
mod common;

#[test]
fn fixture_is_generated_once_and_runs_on_host() {
    let path = common::fixture_binary();
    assert!(path.is_file());
    assert_eq!(path.file_name().unwrap(), common::FIXTURE_PROGRAM);
    assert!(!path.starts_with(env!("CARGO_MANIFEST_DIR")));
    let paths = std::thread::scope(|scope| {
        let threads: Vec<_> = (0..8)
            .map(|_| scope.spawn(common::fixture_binary))
            .collect();
        threads
            .into_iter()
            .map(|t| t.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert!(paths.iter().all(|p| p == &path));
    let output = std::process::Command::new(path).output().unwrap();
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    for expected in [
        "Hello, Ghidra CLI!",
        "10 + 20 = 30",
        "10! = 3628800",
        "fib(20) = 6765",
    ] {
        assert!(stdout.contains(expected), "Missing {expected}: {stdout}");
    }
}

fn doctor_output(success: bool, stdout: &str, stderr: &str) -> std::process::Output {
    // Obtain a portable ExitStatus without platform-specific raw status values.
    let mut output = std::process::Command::new("rustc")
        .arg(if success {
            "--version"
        } else {
            "--not-a-valid-rustc-option"
        })
        .output()
        .unwrap();
    assert_eq!(output.status.success(), success);
    output.stdout = stdout.as_bytes().to_vec();
    output.stderr = stderr.as_bytes().to_vec();
    output
}

const HEALTHY: &str = "analyzeHeadless: OK\nChecking bridge script compiles... OK\n";

#[test]
fn doctor_accepts_successful_headless_and_compile_checks() {
    common::assert_doctor_ready(&doctor_output(true, HEALTHY, ""));
}

#[test]
fn doctor_rejects_failed_exit_even_with_healthy_stdout() {
    let output = doctor_output(false, HEALTHY, "startup failed");
    assert!(std::panic::catch_unwind(|| common::assert_doctor_ready(&output)).is_err());
}

#[test]
fn doctor_rejects_missing_or_failed_checks() {
    for stdout in [
        "",
        "Checking project directory... OK",
        "analyzeHeadless: OK",
        "analyzeHeadless: NOT FOUND\nChecking bridge script compiles... OK",
        "analyzeHeadless: OK\nChecking bridge script compiles... FAILED",
    ] {
        let output = doctor_output(true, stdout, "");
        assert!(
            std::panic::catch_unwind(|| common::assert_doctor_ready(&output)).is_err(),
            "{stdout}"
        );
    }
}

#[test]
fn doctor_failure_includes_stderr() {
    let output = doctor_output(false, "", "failed to create initial log file");
    let panic = std::panic::catch_unwind(|| common::assert_doctor_ready(&output)).unwrap_err();
    let message = panic.downcast_ref::<String>().unwrap();
    assert!(
        message.contains("failed to create initial log file"),
        "{message}"
    );
    assert!(message.contains("Status:"), "{message}");
}

#[test]
fn suite_resources_are_isolated_and_cleaned_on_exit() {
    const CHILD_REPORT: &str = "GHIDRA_HARNESS_CHILD_REPORT";
    if let Some(report) = std::env::var_os(CHILD_REPORT) {
        let fixture = common::fixture_binary();
        std::fs::write(
            report,
            serde_json::to_vec(&(fixture, common::test_project())).unwrap(),
        )
        .unwrap();
        return;
    }

    let reports = tempfile::tempdir().unwrap();
    let mut projects = Vec::new();
    for index in 0..2 {
        let report = reports.path().join(format!("{index}.json"));
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "suite_resources_are_isolated_and_cleaned_on_exit",
            ])
            .env(CHILD_REPORT, &report)
            .env("GHIDRA_CLI_CONFIG", reports.path().join("config.yaml"))
            .env("GHIDRA_PROJECT_DIR", reports.path())
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let (fixture, project): (std::path::PathBuf, String) =
            serde_json::from_slice(&std::fs::read(report).unwrap()).unwrap();
        assert!(
            !fixture.parent().unwrap().exists(),
            "Fixture directory leaked: {fixture:?}"
        );
        projects.push(project);
    }
    assert_ne!(
        projects[0], projects[1],
        "Test runs must not share projects"
    );
}

#[test]
fn disassembly_schema_matches_cli_arrays_and_rejects_wrong_shapes() {
    use common::schemas::{DisasmResult, Validate};
    let output =
        r#"[{"address":"00100000","mnemonic":"MOV","operands":["RAX","RBX"],"bytes":"4889d8"}]"#;
    let disasm: DisasmResult = serde_json::from_str(output).unwrap();
    assert_eq!(disasm.results.len(), 1);
    assert_eq!(disasm.results[0].operands, ["RAX", "RBX"]);
    disasm.results[0].assert_valid();
    let no_operands: DisasmResult = serde_json::from_str(
        r#"[{"address":"00100000","mnemonic":"RET","operands":[],"bytes":"c3"}]"#,
    )
    .unwrap();
    assert!(no_operands.results[0].operands.is_empty());
    for invalid in [
        r#"{"results":[]}"#,
        r#"[{"address":"00100000","mnemonic":"MOV","operands":"RAX, RBX"}]"#,
        r#"[{"address":"00100000","mnemonic":"RET"}]"#,
    ] {
        assert!(
            serde_json::from_str::<DisasmResult>(invalid).is_err(),
            "{invalid}"
        );
    }
}
