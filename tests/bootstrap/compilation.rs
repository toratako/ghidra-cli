use ghidra_cli::ghidra::{bridge, java};
use std::process::Command;
use std::time::Duration;

#[test]
#[serial_test::serial]
fn configured_jdk_launches_when_path_java_is_broken() {
    require_ghidra!();
    let config = ghidra_cli::config::Config::load().unwrap();
    let install = config.get_ghidra_installation().unwrap();
    let jdk = java::resolve_for_ghidra(&install, config.get_java_home()).unwrap();
    let root = tempfile::Builder::new()
        .prefix("jdk launch ")
        .tempdir()
        .unwrap();
    let marker = root.path().join("path-java-invoked");
    let source = root.path().join("java.rs");
    std::fs::write(
        &source,
        r#"fn main() {
    // launch.bat probes java.exe -version before using it for LaunchSupport.
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("-version")) {
        return;
    }
    std::fs::write(std::env::var_os("GHIDRA_CLI_TEST_PATH_JAVA_MARKER").unwrap(), b"called").unwrap();
    std::process::exit(1);
}
"#,
    )
    .unwrap();
    let compiler = Command::new("rustc")
        .arg(&source)
        .arg("-o")
        .arg(
            root.path()
                .join(if cfg!(windows) { "java.exe" } else { "java" }),
        )
        .output()
        .unwrap();
    assert!(compiler.status.success(), "{compiler:?}");
    let mut paths = vec![root.path().to_path_buf()];
    paths.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap()));
    let mut command = Command::new(assert_cmd::cargo::cargo_bin!("ghidra-cli"));
    command
        .args(["doctor", "--runtime", "--json", "--java-home"])
        .arg(&jdk.home)
        .arg("--projects-dir")
        .arg(root.path().join("projects"))
        .env("PATH", std::env::join_paths(paths).unwrap())
        .env("GHIDRA_CLI_TEST_PATH_JAVA_MARKER", &marker);
    let output =
        crate::common::run_command_with_output(&mut command, Duration::from_secs(120)).unwrap();
    crate::common::assert_doctor_ready(&output);
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["data"]["runtime"]["status"], "success");
    assert!(!marker.exists(), "Launcher used broken PATH Java");
    assert_eq!(
        std::fs::read_dir(root.path().join("projects"))
            .unwrap()
            .count(),
        0,
        "Runtime check must stop the bridge and remove its project"
    );
}

#[cfg(unix)]
#[test]
#[serial_test::serial]
fn configured_jdk_with_path_separator_remains_usable() {
    require_ghidra!();
    let config = ghidra_cli::config::Config::load().unwrap();
    let install = config.get_ghidra_installation().unwrap();
    let jdk = java::resolve_for_ghidra(&install, config.get_java_home()).unwrap();
    let root = tempfile::Builder::new()
        .prefix("jdk-path-")
        .tempdir()
        .unwrap();
    let selected = root.path().join("selected:jdk");
    let bootstrap = root.path().join("bootstrap-jdk");
    std::os::unix::fs::symlink(&jdk.home, &selected).unwrap();
    std::os::unix::fs::symlink(&jdk.home, &bootstrap).unwrap();
    let mut paths = vec![bootstrap.join("bin")];
    paths.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap()));
    let mut command = Command::new(assert_cmd::cargo::cargo_bin!("ghidra-cli"));
    command
        .args(["doctor", "--runtime", "--json", "--java-home"])
        .arg(&selected)
        .arg("--projects-dir")
        .arg(root.path().join("projects"))
        .env("PATH", std::env::join_paths(paths).unwrap());
    let output =
        crate::common::run_command_with_output(&mut command, Duration::from_secs(240)).unwrap();
    crate::common::assert_doctor_ready(&output);
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["data"]["runtime"]["status"], "success");
}

#[test]
fn doctor_compiles_from_quoted_temporary_directory() {
    require_ghidra!();
    let root = tempfile::Builder::new()
        .prefix("javac temp's #日本語 ")
        .tempdir()
        .unwrap();
    let mut command = Command::new(assert_cmd::cargo::cargo_bin!("ghidra-cli"));
    command
        .args(["doctor", "--json"])
        .env("TMPDIR", root.path())
        .env("TMP", root.path())
        .env("TEMP", root.path());
    let output =
        crate::common::run_command_with_output(&mut command, Duration::from_secs(120)).unwrap();
    crate::common::assert_doctor_ready(&output);
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
}

#[test]
fn bridge_compiles_with_long_relative_classpath_and_quoted_paths() {
    require_ghidra!();
    let config = ghidra_cli::config::Config::load().unwrap();
    let install = config.get_ghidra_installation().unwrap();
    let jdk = java::resolve_for_ghidra(&install, config.get_java_home()).unwrap();
    let working_dir = std::env::current_dir().unwrap();
    let root = tempfile::Builder::new()
        .prefix("javac classpath's #日本語 ")
        .tempdir_in(&working_dir)
        .unwrap();
    // Windows paths already contain backslashes. On Unix also exercise literal
    // backslashes, double quotes and newlines in a directory name.
    #[cfg(unix)]
    let jars = root.path().join("jars\\with\"quotes\nand\rcarriage-return");
    #[cfg(not(unix))]
    let jars = root.path().join("jars");
    std::fs::create_dir(&jars).unwrap();

    let mut classpath_length = 0;
    let mut count = 0;
    for entry in walkdir::WalkDir::new(&install.path) {
        let entry = entry.unwrap();
        if entry.path().extension().is_some_and(|ext| ext == "jar") {
            let path = jars.join(format!("dependency-{count}.jar"));
            // Prefer links to avoid copying the whole installation; the temp
            // directory may be on a different filesystem from Ghidra.
            if std::fs::hard_link(entry.path(), &path).is_err() {
                std::fs::copy(entry.path(), &path).unwrap();
            }
            classpath_length += path.to_string_lossy().encode_utf16().count() + 1;
            count += 1;
        }
    }
    assert!(count > 0, "No Ghidra jars found");
    // Valid empty jars pad the classpath without adding conflicting classes.
    while classpath_length <= 40_000 {
        let path = jars.join(format!("padding-{count}.jar"));
        zip::ZipWriter::new(std::fs::File::create(&path).unwrap())
            .finish()
            .unwrap();
        classpath_length += path.to_string_lossy().encode_utf16().count() + 1;
        count += 1;
    }

    // The compiler runs in its own temporary directory. Relative inputs must
    // still resolve against the caller's directory.
    let relative_jars = jars.strip_prefix(&working_dir).unwrap();
    let mut classpath_installation = install;
    classpath_installation.path = relative_jars.to_path_buf();
    classpath_installation.kind = ghidra_cli::ghidra::installation::InstallationKind::Directory;
    bridge::compile_check(&classpath_installation, &jdk.home)
        .unwrap_or_else(|error| panic!("{error}"));
}
