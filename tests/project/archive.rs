use crate::{common, json_output};
use ghidra_cli::ghidra::bridge;
use serde_json::Value;
use serial_test::serial;
use std::path::Path;
use std::process::{Command, Output};
use std::time::Duration;

fn archive(project: &Path, output: &Path) -> anyhow::Result<Output> {
    common::run_command_with_output(
        Command::new(assert_cmd::cargo::cargo_bin!("ghidra-cli"))
            .args(["--json", "project", "archive"])
            .arg(project)
            .arg("--output")
            .arg(output),
        Duration::from_secs(120),
    )
}

fn restore(archive: &Path, project: &Path) -> anyhow::Result<Output> {
    common::run_command_with_output(
        Command::new(assert_cmd::cargo::cargo_bin!("ghidra-cli"))
            .args(["--json", "project", "restore"])
            .arg(archive)
            .arg(project),
        Duration::from_secs(120),
    )
}

fn success(output: Output) -> anyhow::Result<Value> {
    anyhow::ensure!(output.status.success(), "{output:?}");
    json_output::from_slice(&output.stdout).map_err(Into::into)
}

fn verify(project: &Path) -> anyhow::Result<()> {
    let harness =
        common::DaemonTestHarness::new(project.to_str().unwrap(), common::FIXTURE_PROGRAM)?;
    let client = harness.client()?;
    assert_eq!(client.list_programs()?["count"], 2);
    client.script_run_source(include_str!("VerifyArchiveFixture.java"), &[], &[], false)?;
    drop(harness);
    Ok(())
}

#[test]
#[serial]
fn gar_round_trip_preserves_project_and_interoperates_with_native_ghidra() -> anyhow::Result<()> {
    require_ghidra!();
    let root = tempfile::Builder::new()
        .prefix("ghidra gar space ")
        .tempdir()?;
    let project = root.path().join("original.v1/project");
    common::fixture::copy_analyzed_project(&project)?;
    let harness =
        common::DaemonTestHarness::new(project.to_str().unwrap(), common::FIXTURE_PROGRAM)?;
    harness.client()?.script_run_source(
        include_str!("CreateArchiveFixture.java"),
        &[],
        &[],
        false,
    )?;
    let pid = bridge::read_pid_file(&project)?.unwrap();
    let backups = root.path().join(".backups");
    std::fs::create_dir(&backups)?;
    let gar = backups.join("snapshot 'quoted'.gar");
    let alias = root.path().join(if cfg!(windows) {
        "original.v1/./PROJECT"
    } else {
        "original.v1/./project"
    });
    let receipt = success(archive(&alias, &gar)?)?;
    assert_eq!(receipt["bridge_state"], "stopped");
    assert_eq!(receipt["snapshot"], "saved_local_contents");
    assert_eq!(receipt["files"], 3);
    assert_eq!(receipt["folders"], 3);
    assert!(!bridge::is_pid_alive(pid));
    let mut zip = zip::ZipArchive::new(std::fs::File::open(&gar)?)?;
    let marker = format!("{}.gpr", alias.file_name().unwrap().to_string_lossy());
    assert!(zip.by_name(&marker).is_ok());
    drop(zip);
    drop(harness);
    let restored = root.path().join("restored.v2");
    let receipt = success(common::run_command_with_output(
        Command::new(assert_cmd::cargo::cargo_bin!("ghidra-cli"))
            .args([
                "--json",
                "--project",
                "ignored",
                "--program",
                "ignored",
                "--projects-dir",
            ])
            .arg(root.path())
            .args(["project", "restore"])
            .arg(&gar)
            .arg("restored.v2"),
        Duration::from_secs(120),
    )?)?;
    assert_eq!(receipt["project_path"], restored.to_string_lossy().as_ref());
    assert_eq!(receipt["files"], 3);
    assert!(bridge::read_pid_file(&restored)?.is_none());
    verify(&restored)?;

    // Native creation/restoration execute on an unrelated bridge with no open
    // references to either archive project.
    let worker = root.path().join("worker/project");
    common::fixture::copy_analyzed_project(&worker)?;
    let worker = common::DaemonTestHarness::new(worker.to_str().unwrap(), common::FIXTURE_PROGRAM)?;
    let native_restored = root.path().join("native-restored");
    worker.client()?.script_run_source(
        include_str!("NativeGar.java"),
        &[
            "restore".into(),
            native_restored.to_string_lossy().into_owned(),
            gar.to_string_lossy().into_owned(),
        ],
        &[],
        false,
    )?;
    verify(&native_restored)?;
    let native_gar = root.path().join("native.gar");
    worker.client()?.script_run_source(
        include_str!("NativeGar.java"),
        &[
            "archive".into(),
            project.to_string_lossy().into_owned(),
            native_gar.to_string_lossy().into_owned(),
        ],
        &[],
        false,
    )?;
    let from_native = root.path().join("from-native");
    success(restore(&native_gar, &from_native)?)?;
    verify(&from_native)?;

    // Exercise Windows-native entry names on every host, using real project data.
    let windows_gar = root.path().join("windows.gar");
    let mut source = zip::ZipArchive::new(std::fs::File::open(&native_gar)?)?;
    let mut windows = zip::ZipWriter::new(std::fs::File::create(&windows_gar)?);
    let options = zip::write::SimpleFileOptions::default();
    for index in 0..source.len() {
        let mut entry = source.by_index(index)?;
        if entry.is_dir() {
            continue;
        }
        windows.start_file(entry.name().replace('/', "\\"), options)?;
        std::io::copy(&mut entry, &mut windows)?;
    }
    for excluded in ["save\\ignored", "idata\\00\\.properties"] {
        windows.start_file(excluded, options)?;
        std::io::Write::write_all(&mut windows, b"excluded project state")?;
    }
    drop(windows.finish()?);
    let from_windows = root.path().join("from-windows");
    success(restore(&windows_gar, &from_windows)?)?;
    let data = from_windows.with_added_extension("rep");
    assert!(!data.join("save").exists());
    assert!(!data.join("idata/00/.properties").exists());
    verify(&from_windows)?;

    worker.client()?.script_run_source(
        include_str!("CheckGarFailures.java"),
        &[
            root.path().to_string_lossy().into_owned(),
            project.to_string_lossy().into_owned(),
            gar.to_string_lossy().into_owned(),
        ],
        &[],
        false,
    )?;
    Ok(())
}

#[test]
#[serial]
fn gar_conflicts_preserve_live_bridge_and_save_failure_remains_recoverable() -> anyhow::Result<()> {
    require_ghidra!();
    let root = tempfile::Builder::new()
        .prefix("ghidra-gar-failure-")
        .tempdir()?;
    let project = root.path().join("project");
    common::fixture::copy_analyzed_project(&project)?;
    let harness =
        common::DaemonTestHarness::new(project.to_str().unwrap(), common::FIXTURE_PROGRAM)?;
    let client = harness.client()?;
    let pid = bridge::read_pid_file(&project)?.unwrap();
    let gar = root.path().join("snapshot.gar");
    std::fs::write(&gar, b"existing archive")?;
    let conflict = archive(&project, &gar)?;
    assert!(!conflict.status.success());
    assert!(bridge::is_pid_alive(pid));
    assert_eq!(std::fs::read(&gar)?, b"existing archive");
    std::fs::remove_file(&gar)?;
    let recursive = project.with_added_extension("rep").join("recursive.gar");
    assert!(!archive(&project, &recursive)?.status.success());
    assert!(bridge::is_pid_alive(pid));
    assert!(!recursive.exists());
    #[cfg(unix)]
    {
        // A symlink of .rep alone shares data but not Ghidra's sibling lock.
        let alias = root.path().join("alias");
        std::os::unix::fs::symlink(
            project.with_added_extension("rep"),
            alias.with_added_extension("rep"),
        )?;
        std::fs::write(alias.with_added_extension("gpr"), [])?;
        let output = archive(&alias, &gar)?;
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("real project base path"));
        assert!(bridge::is_pid_alive(pid));
        std::fs::remove_file(alias.with_added_extension("rep"))?;
        std::fs::remove_file(alias.with_added_extension("gpr"))?;
    }
    let transaction = client
        .script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
public class BlockArchiveSave extends GhidraScript {
    public void run() throws Exception {
        println(Integer.toString(currentProgram.startTransaction("hold archive save")));
    }
}
"#,
            &[],
            &[],
            false,
        )
        .unwrap_err();
    let transaction = transaction
        .downcast_ref::<ghidra_cli::ipc::protocol::BridgeCommandError>()
        .unwrap()
        .detail["command_response"]["data"]["stdout"]
        .as_str()
        .unwrap()
        .trim()
        .to_owned();
    let failed = archive(&project, &gar)?;
    client.script_run_source(r#"
import ghidra.app.script.GhidraScript;
public class ReleaseArchiveSave extends GhidraScript {
    public void run() throws Exception { currentProgram.endTransaction(Integer.parseInt(getScriptArgs()[0]), true); }
}
"#, &[transaction], &[], false)?;
    assert!(!failed.status.success());
    let error: Value = serde_json::from_slice(&failed.stderr)?;
    assert_eq!(error["detail"]["save_failed"], true);
    assert_eq!(error["detail"]["bridge_state"], "running");
    assert!(bridge::is_pid_alive(pid));
    assert!(!gar.exists());
    success(archive(&project, &gar)?)?;
    drop(harness);
    for suffix in ["gpr", "rep"] {
        let target = root.path().join(format!("partial-{suffix}"));
        let artifact = target.with_added_extension(suffix);
        if suffix == "rep" {
            std::fs::create_dir(&artifact)?;
        } else {
            std::fs::write(&artifact, b"keep")?;
        }
        assert!(!restore(&gar, &target)?.status.success());
        assert!(artifact.exists());
    }
    assert!(!restore(&gar, &project)?.status.success());
    assert_eq!(std::fs::read_dir(root.path())?.count(), 5);
    Ok(())
}

#[test]
#[serial]
fn gar_rejects_malformed_archives_without_publishing_or_leaving_staging() -> anyhow::Result<()> {
    use std::io::Write;
    require_ghidra!();
    let root = tempfile::Builder::new()
        .prefix("ghidra-gar-invalid-")
        .tempdir()?;
    let target = root.path().join("restored");
    let file = root.path().join("invalid.gar");
    for unsafe_name in [
        "../escaped",
        "/absolute",
        "idata/../../escaped",
        "idata\\../..\\escaped",
        "\\absolute",
        "C:/escape",
    ]
    .into_iter()
    .chain(cfg!(windows).then_some("idata/NUL"))
    {
        let mut zip = zip::ZipWriter::new(std::fs::File::create(&file)?);
        zip.start_file("JAR_FORMAT", zip::write::SimpleFileOptions::default())?;
        zip.start_file(unsafe_name, zip::write::SimpleFileOptions::default())?;
        zip.write_all(b"invalid")?;
        zip.finish()?;
        let output = restore(&file, &target)?;
        assert!(!output.status.success(), "{unsafe_name}: {output:?}");
        let error: Value = serde_json::from_slice(&output.stderr)?;
        assert_eq!(
            error["detail"]["stage"], "project.restore_extract",
            "{error}"
        );
        assert!(
            error["detail"]["cause"]
                .as_str()
                .unwrap()
                .contains("Unsafe GAR"),
            "{error}"
        );
        assert!(!target.with_added_extension("rep").exists());
        assert!(!target.with_added_extension("gpr").exists());
        assert_eq!(std::fs::read_dir(root.path())?.count(), 1, "{output:?}");
    }
    // ZIP writers reject duplicate names, so construct a valid pair and change
    // the equal-length local/central names to collide after finalization.
    for fault in ["duplicate", "separator_duplicate", "crc", "file_directory"] {
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        zip.start_file("JAR_FORMAT", options)?;
        zip.start_file("idata/a", options)?;
        zip.write_all(b"unique-payload")?;
        zip.start_file(
            match fault {
                "file_directory" => "idata\\a/b",
                "separator_duplicate" => "idata\\a",
                _ => "idata/b",
            },
            options,
        )?;
        zip.write_all(b"second")?;
        let mut bytes = zip.finish()?.into_inner();
        if fault == "duplicate" {
            for index in 0..bytes.len() - 7 {
                if &bytes[index..index + 7] == b"idata/b" {
                    bytes[index + 6] = b'a';
                }
            }
        } else if fault == "crc" {
            let index = bytes
                .windows(14)
                .position(|data| data == b"unique-payload")
                .unwrap();
            bytes[index] ^= 1;
        }
        std::fs::write(&file, bytes)?;
        let output = restore(&file, &target)?;
        assert!(!output.status.success(), "{fault}: {output:?}");
        let error: Value = serde_json::from_slice(&output.stderr)?;
        assert_eq!(
            error["detail"]["stage"], "project.restore_extract",
            "{error}"
        );
        assert_eq!(error["detail"]["published"], false);
        if fault == "separator_duplicate" {
            assert!(error["detail"]["cause"]
                .as_str()
                .unwrap()
                .contains("Duplicate GAR entry: idata/a"));
        }
        assert_eq!(std::fs::read_dir(root.path())?.count(), 1, "{error}");
    }
    std::fs::write(&file, b"not a zip")?;
    let output = restore(&file, &target)?;
    assert!(!output.status.success());
    let error: Value = serde_json::from_slice(&output.stderr)?;
    assert_eq!(
        error["detail"]["stage"], "project.restore_extract",
        "{error}"
    );
    assert_eq!(std::fs::read_dir(root.path())?.count(), 1);
    Ok(())
}

#[test]
#[serial]
fn gar_reports_unavailable_external_link_targets_without_following_them() -> anyhow::Result<()> {
    require_ghidra!();
    let root = tempfile::Builder::new()
        .prefix("ghidra-gar-links-")
        .tempdir()?;
    let project = root.path().join("main/project");
    let external = root.path().join("external/project");
    common::fixture::copy_analyzed_project(&project)?;
    common::fixture::copy_analyzed_project(&external)?;
    let harness =
        common::DaemonTestHarness::new(project.to_str().unwrap(), common::FIXTURE_PROGRAM)?;
    harness.client()?.script_run_source(r#"
import ghidra.app.script.GhidraScript;
import ghidra.base.project.GhidraProject;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import java.nio.file.Path;
public class CreateExternalGarLink extends GhidraScript {
    public void run() throws Exception {
        Path path = Path.of(getScriptArgs()[0]);
        var external = GhidraProject.openProject(path.getParent().toString(), path.getFileName().toString(), false);
        try {
            var file = external.getProject().getProjectData().getRootFolder().getFile(getScriptArgs()[1]);
            var destination = state.getProject().getProjectData().getRootFolder().createFolder("external");
            try { DomainFile.class.getMethod("copyToAsLink", DomainFolder.class, boolean.class).invoke(file, destination, false); }
            catch (NoSuchMethodException olderGhidra) { DomainFile.class.getMethod("copyToAsLink", DomainFolder.class).invoke(file, destination); }
        } finally { external.close(); }
    }
}
"#, &[external.to_string_lossy().into_owned(), common::FIXTURE_PROGRAM.into()], &[], false)?;
    std::fs::remove_dir_all(external.with_added_extension("rep"))?;
    std::fs::remove_file(external.with_added_extension("gpr"))?;
    let gar = root.path().join("links.gar");
    let result = success(archive(&project, &gar)?)?;
    assert_eq!(result["external_dependencies"]["complete"], true);
    let links = result["external_dependencies"]["links"].as_array().unwrap();
    assert_eq!(links.len(), 1, "{result}");
    assert_eq!(links[0]["direct_external"], true);
    assert!(links[0]["target"]
        .as_str()
        .unwrap()
        .contains("external/project"));
    drop(harness);
    let restored = success(restore(&gar, &root.path().join("restored"))?)?;
    assert_eq!(
        restored["external_dependencies"],
        result["external_dependencies"]
    );
    Ok(())
}
