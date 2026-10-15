use crate::common;
use serde_json::Value;
use serial_test::serial;
use std::{path::Path, process::Command, time::Duration};

fn delete(project: &Path, projects_dir: &Path) -> std::process::Output {
    common::run_command_with_output(
        Command::new(assert_cmd::cargo::cargo_bin!("ghidra-cli"))
            .args(["--json", "--projects-dir"])
            .arg(projects_dir)
            .args(["project", "delete"])
            .arg(project),
        Duration::from_secs(120),
    )
    .unwrap()
}

#[test]
#[serial]
fn project_delete_rejects_names_that_native_ghidra_would_change() {
    require_ghidra!();
    let root = tempfile::Builder::new()
        .prefix("ghidra deletion identity ")
        .tempdir()
        .unwrap();
    let victim = root.path().join("victim");
    let requested = root.path().join("victim.gpr");
    for project in [&victim, &requested] {
        std::fs::write(project.with_added_extension("gpr"), b"preserved marker").unwrap();
        let data = project.with_added_extension("rep");
        std::fs::create_dir(&data).unwrap();
        std::fs::write(data.join("preserved"), b"preserved project contents").unwrap();
    }

    for operand in [Path::new("victim.gpr"), requested.as_path()] {
        let output = delete(operand, root.path());
        assert!(!output.status.success(), "{output:?}");
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert!(
            error["message"]
                .as_str()
                .unwrap()
                .contains("project base path without the .gpr suffix"),
            "{error}"
        );
        for project in [&victim, &requested] {
            assert_eq!(
                std::fs::read(project.with_added_extension("gpr")).unwrap(),
                b"preserved marker"
            );
            assert_eq!(
                std::fs::read(project.with_added_extension("rep").join("preserved")).unwrap(),
                b"preserved project contents"
            );
        }
    }
}

#[cfg(unix)]
#[test]
#[serial]
fn project_delete_rejects_parent_paths_that_native_ghidra_would_redirect() {
    require_ghidra!();
    let root = tempfile::Builder::new()
        .prefix("ghidra-deletion-parent-identity-")
        .tempdir()
        .unwrap();
    let requested = root.path().join("parent\\child/project");
    let redirected = root.path().join("parent/child/project");
    for project in [&requested, &redirected] {
        std::fs::create_dir_all(project.parent().unwrap()).unwrap();
        std::fs::write(project.with_added_extension("gpr"), b"preserved marker").unwrap();
        let data = project.with_added_extension("rep");
        std::fs::create_dir(&data).unwrap();
        std::fs::write(data.join("preserved"), b"preserved project contents").unwrap();
    }

    let output = delete(&requested, root.path());
    assert!(!output.status.success(), "{output:?}");
    for project in [&requested, &redirected] {
        assert_eq!(
            std::fs::read(project.with_added_extension("gpr")).unwrap(),
            b"preserved marker"
        );
        assert_eq!(
            std::fs::read(project.with_added_extension("rep").join("preserved")).unwrap(),
            b"preserved project contents"
        );
    }
}

#[cfg(unix)]
#[test]
#[serial]
fn project_delete_removes_links_without_following_them() {
    require_ghidra!();
    let root = tempfile::Builder::new()
        .prefix("ghidra-deletion-links-")
        .tempdir()
        .unwrap();
    let external = root.path().join("external");
    std::fs::create_dir(&external).unwrap();
    std::fs::write(external.join("preserved"), b"external contents").unwrap();
    for (name, target) in [
        ("linked-project", external.clone()),
        ("dangling-project", root.path().join("missing")),
    ] {
        let project = root.path().join(name);
        let data = project.with_added_extension("rep");
        std::os::unix::fs::symlink(target, &data).unwrap();
        std::fs::write(project.with_added_extension("gpr"), []).unwrap();
        let output = delete(&project, root.path());
        assert!(output.status.success(), "{output:?}");
        let result: Value = crate::json_output::from_slice(&output.stdout).unwrap();
        assert_eq!(result["deleted"], true, "{result}");
        assert!(!project.with_added_extension("gpr").exists());
        assert!(std::fs::symlink_metadata(&data).is_err());
        assert_eq!(
            std::fs::read(external.join("preserved")).unwrap(),
            b"external contents"
        );
    }

    // Partial projects can consist of only one dangling artifact. The Rust
    // preflight must still invoke the locked bootstrap to remove that entry.
    for suffix in ["gpr", "rep"] {
        let project = root.path().join(format!("lone-{suffix}"));
        let artifact = project.with_added_extension(suffix);
        std::os::unix::fs::symlink(root.path().join("missing"), &artifact).unwrap();
        let output = delete(&project, root.path());
        assert!(output.status.success(), "{output:?}");
        let result: Value = crate::json_output::from_slice(&output.stdout).unwrap();
        assert_eq!(result["deleted"], true, "{result}");
        assert!(std::fs::symlink_metadata(&artifact).is_err());
    }
}
