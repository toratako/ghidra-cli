//! Regression tests for fixture generation and fail-closed test prerequisites.
mod common;

#[test]
fn fixture_function_lookup_prefers_exact_names_and_preserves_fallbacks() {
    use common::helpers::find_fixture_function;
    use common::schemas::Function;

    let functions: Vec<Function> = ["__libc_start_main", "_main", "main", "sample_binary::main"]
        .into_iter()
        .enumerate()
        .map(|(index, name)| {
            serde_json::from_value(serde_json::json!({
                "name": name,
                "address": format!("0x{index:08x}"),
                "entry_point": format!("0x{index:08x}"),
                "size": 1,
                "is_external": false,
                "entry_memory": null,
            }))
            .unwrap()
        })
        .collect();

    assert_eq!(
        find_fixture_function(&functions, "main").unwrap().address,
        "0x00000002"
    );
    assert_eq!(
        find_fixture_function(&functions[..2], "main").unwrap().name,
        "_main"
    );
    assert_eq!(
        find_fixture_function(&functions[3..], "main").unwrap().name,
        "sample_binary::main"
    );
    // Preserve first-match behavior when only substring fallbacks exist.
    let decorated = [functions[0].clone(), functions[3].clone()];
    assert_eq!(
        find_fixture_function(&decorated, "main").unwrap().name,
        "__libc_start_main"
    );
    assert_eq!(
        find_fixture_function(&functions, "libc").unwrap().name,
        "__libc_start_main"
    );
    assert!(find_fixture_function(&functions, "missing").is_none());
    assert!(find_fixture_function(&[], "main").is_none());
}

#[test]
fn command_output_returns_while_descendant_holds_streams() {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    const MODE: &str = "GHIDRA_OUTPUT_TEST_MODE";
    const ROOT: &str = "GHIDRA_OUTPUT_TEST_ROOT";
    let executable = std::env::current_exe().unwrap();
    let command = || {
        let mut command = Command::new(&executable);
        command.args([
            "--exact",
            "command_output_returns_while_descendant_holds_streams",
            "--nocapture",
        ]);
        command
    };
    if let Ok(mode) = std::env::var(MODE) {
        let root = std::path::PathBuf::from(std::env::var_os(ROOT).unwrap());
        if mode == "descendant" {
            println!("descendant stdout");
            eprintln!("descendant stderr");
            std::fs::write(root.join("ready"), "").unwrap();
            let started = Instant::now();
            while !root.join("release").exists() && started.elapsed() < Duration::from_secs(15) {
                std::thread::sleep(Duration::from_millis(20));
            }
            std::fs::write(root.join("done"), "").unwrap();
            return;
        }
        println!("parent stdout");
        eprintln!("parent stderr");
        let mut descendant = command()
            .env(MODE, "descendant")
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let started = Instant::now();
        while !root.join("ready").exists() {
            if started.elapsed() > Duration::from_secs(10) {
                let _ = descendant.kill();
                let _ = descendant.wait();
                panic!("Descendant did not start");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        // Intentionally leave the descendant holding both output handles.
        std::process::exit(7);
    }

    let root = tempfile::tempdir().unwrap();
    let result = common::run_command_with_output(
        command().env(MODE, "parent").env(ROOT, root.path()),
        Duration::from_secs(10),
    );
    let returned_before_descendant = !root.path().join("done").exists();
    std::fs::write(root.path().join("release"), "").unwrap();
    let started = Instant::now();
    while !root.path().join("done").exists() {
        assert!(started.elapsed() < Duration::from_secs(10));
        std::thread::sleep(Duration::from_millis(20));
    }
    let output = result.unwrap();
    assert!(returned_before_descendant, "Waited for descendant EOF");
    assert_eq!(output.status.code(), Some(7));
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stdout.contains("parent stdout"), "{stdout}");
    assert!(stdout.contains("descendant stdout"), "{stdout}");
    assert!(stderr.contains("parent stderr"), "{stderr}");
    assert!(stderr.contains("descendant stderr"), "{stderr}");
}

#[test]
fn command_output_timeout_reaps_child_and_keeps_diagnostics() {
    use std::time::{Duration, Instant};

    const REPORT: &str = "GHIDRA_OUTPUT_TIMEOUT_REPORT";
    if let Some(report) = std::env::var_os(REPORT) {
        println!("stdout before timeout");
        eprintln!("stderr before timeout");
        std::fs::write(report, std::process::id().to_string()).unwrap();
        std::thread::sleep(Duration::from_secs(30));
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let report = root.path().join("pid");
    let started = Instant::now();
    let error = common::run_command_with_output(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "command_output_timeout_reaps_child_and_keeps_diagnostics",
                "--nocapture",
            ])
            .env(REPORT, &report),
        Duration::from_secs(5),
    )
    .unwrap_err();
    assert!(started.elapsed() < Duration::from_secs(20));
    let diagnostic = format!("{error:#}");
    assert!(diagnostic.contains("timed out after 5s"), "{diagnostic}");
    assert!(diagnostic.contains("stdout before timeout"), "{diagnostic}");
    assert!(diagnostic.contains("stderr before timeout"), "{diagnostic}");
    let pid = std::fs::read_to_string(report).unwrap().parse().unwrap();
    assert!(!ghidra_cli::ghidra::bridge::is_pid_alive(pid));
}

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

const HEALTHY: &str =
    "Headless launcher: OK (analyzeHeadless)\nChecking bridge script compiles... OK\n";

#[test]
fn doctor_accepts_successful_headless_and_compile_checks() {
    for launcher in ["analyzeHeadless", "java -jar"] {
        let healthy = HEALTHY.replace("analyzeHeadless", launcher);
        common::assert_doctor_ready(&doctor_output(true, &healthy, ""));
    }
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
        "Headless launcher: OK (analyzeHeadless)",
        "Headless launcher: NOT FOUND\nChecking bridge script compiles... OK",
        "Headless launcher: OK (analyzeHeadless)\nChecking bridge script compiles... FAILED",
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
            .env_remove(common::fixture::RUN_DIR_ENV)
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
fn doctor_runs_once_for_concurrent_callers() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let check = common::DoctorCheck::default();
    let calls = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                check.require_with(|| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(doctor_output(true, HEALTHY, ""))
                });
            });
        }
    });
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn doctor_failure_is_replayed_without_rerunning() {
    let check = common::DoctorCheck::default();
    assert!(std::panic::catch_unwind(|| {
        check.require_with(|| Ok(doctor_output(false, HEALTHY, "broken JDK")));
    })
    .is_err());
    let panic = std::panic::catch_unwind(|| {
        check.require_with(|| panic!("doctor ran again"));
    })
    .unwrap_err();
    assert!(panic
        .downcast_ref::<String>()
        .unwrap()
        .contains("broken JDK"));

    let check = common::DoctorCheck::default();
    for _ in 0..2 {
        let panic = std::panic::catch_unwind(|| {
            check.require_with(|| Err("cannot spawn doctor".to_string()));
        })
        .unwrap_err();
        assert!(panic
            .downcast_ref::<String>()
            .unwrap()
            .contains("cannot spawn doctor"));
    }
}

#[test]
fn shared_fixture_survives_suite_exit() {
    const REPORT: &str = "GHIDRA_SHARED_FIXTURE_REPORT";
    if let Some(report) = std::env::var_os(REPORT) {
        std::fs::write(report, common::fixture_binary().to_str().unwrap()).unwrap();
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let mut paths = Vec::new();
    for i in 0..2 {
        let report = root.path().join(format!("report-{i}"));
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "shared_fixture_survives_suite_exit"])
            .env(common::fixture::RUN_DIR_ENV, root.path())
            .env(REPORT, &report)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        paths.push(std::path::PathBuf::from(
            std::fs::read_to_string(report).unwrap(),
        ));
    }
    assert_eq!(paths[0], paths[1]);
    assert!(
        paths[0].is_file(),
        "A suite removed the run's shared fixture"
    );
    root.close().unwrap();
    assert!(!paths[0].exists());
}

fn fake_project(dir: &std::path::Path) -> anyhow::Result<()> {
    std::fs::write(dir.join("project.gpr"), b"")?;
    std::fs::create_dir_all(dir.join("project.rep/idata/00"))?;
    std::fs::write(dir.join("project.rep/idata/00/data"), b"original")?;
    Ok(())
}

#[test]
fn fixture_publication_is_serialized_across_processes() {
    const ROOT: &str = "GHIDRA_PUBLICATION_TEST_ROOT";
    if let Some(root) = std::env::var_os(ROOT) {
        let root = std::path::PathBuf::from(root);
        let source = common::fixture::publish_once(&root, "analyzed", |dir| {
            // create_new makes duplicate initialization fail even if serialized.
            std::fs::File::create_new(root.join("built-once"))?;
            fake_project(dir)
        })
        .unwrap();
        assert_eq!(
            std::fs::read(source.join("project.rep/idata/00/data")).unwrap(),
            b"original"
        );
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let children: Vec<_> = (0..4)
        .map(|_| {
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "fixture_publication_is_serialized_across_processes",
                ])
                .env(ROOT, root.path())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect();
    for child in children {
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "{output:?}");
    }
}

#[test]
fn failed_fixture_is_not_published_or_rebuilt_in_the_same_run() {
    let root = tempfile::tempdir().unwrap();
    let error = common::fixture::publish_once(root.path(), "analyzed", |dir| {
        fake_project(dir)?;
        anyhow::bail!("analysis failed")
    })
    .unwrap_err();
    assert!(error.to_string().contains("analysis failed"));
    assert!(!root.path().join("analyzed").exists());
    let error = common::fixture::publish_once(root.path(), "analyzed", |_| {
        panic!("Failed analysis ran again");
    })
    .unwrap_err();
    assert!(error.to_string().contains("analysis failed"));
    let next_run = tempfile::tempdir().unwrap();
    assert!(common::fixture::publish_once(next_run.path(), "analyzed", fake_project).is_ok());
}

#[test]
fn project_copies_do_not_share_files_or_overwrite_existing_projects() {
    let root = tempfile::tempdir().unwrap();
    let seed = root.path().join("source");
    std::fs::create_dir(&seed).unwrap();
    fake_project(&seed).unwrap();
    std::fs::write(seed.join("project.lock"), b"stale").unwrap();
    let first = root.path().join("first/project");
    let second = root.path().join("second/project");
    common::fixture::copy_project(&seed.join("project"), &first).unwrap();
    common::fixture::copy_project(&seed.join("project"), &second).unwrap();
    std::fs::write(
        first.with_extension("rep").join("idata/00/data"),
        b"changed",
    )
    .unwrap();
    for project in [&seed.join("project"), &second] {
        assert_eq!(
            std::fs::read(project.with_extension("rep").join("idata/00/data")).unwrap(),
            b"original"
        );
    }
    assert!(!first.with_extension("lock").exists());
    assert!(common::fixture::copy_project(&seed.join("project"), &first).is_err());
    assert_eq!(
        std::fs::read(first.with_extension("rep").join("idata/00/data")).unwrap(),
        b"changed"
    );
}

#[test]
fn address_schema_requires_explicit_hexadecimal_components() {
    use common::schemas::{is_memory_address, Instruction, Validate};

    for address in [
        "0x00401000",
        "overlay:0x1000",
        ".comment:0x00000000",
        "0x1234:0x0005",
        "ram:0x1234:0x0005",
        "0xbank:0x0001",
        "0x10.1",
        "ram:0x10.1",
    ] {
        assert!(is_memory_address(address), "{address}");
        let instruction: Instruction = serde_json::from_value(serde_json::json!({
            "address": address, "mnemonic": "NOP", "operands": [], "bytes": "90",
        }))
        .unwrap();
        instruction.assert_valid();
    }

    for address in [
        "00401000",
        "FUN_00401000",
        "overlay:1000",
        ".comment::00000000",
        "0x1234:0005",
        "ram:1234:0x0005",
        "0x10.",
        "0x10.1.2",
        "ram:0x1234:0x0005.1",
        "0x",
    ] {
        assert!(!is_memory_address(address), "{address}");
    }
}

#[test]
fn disassembly_schema_matches_cli_arrays_and_rejects_wrong_shapes() {
    use common::schemas::{DisasmResult, Validate};
    let output =
        r#"[{"address":"0x00100000","mnemonic":"MOV","operands":["RAX","RBX"],"bytes":"4889d8"}]"#;
    let disasm: DisasmResult = serde_json::from_str(output).unwrap();
    assert_eq!(disasm.results.len(), 1);
    assert_eq!(disasm.results[0].operands, ["RAX", "RBX"]);
    disasm.results[0].assert_valid();
    let no_operands: DisasmResult = serde_json::from_str(
        r#"[{"address":"0x00100000","mnemonic":"RET","operands":[],"bytes":"c3"}]"#,
    )
    .unwrap();
    assert!(no_operands.results[0].operands.is_empty());
    for invalid in [
        r#"{"results":[]}"#,
        r#"[{"address":"0x00100000","mnemonic":"MOV","operands":"RAX, RBX"}]"#,
        r#"[{"address":"0x00100000","mnemonic":"RET"}]"#,
    ] {
        assert!(
            serde_json::from_str::<DisasmResult>(invalid).is_err(),
            "{invalid}"
        );
    }
}
