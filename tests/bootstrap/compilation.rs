use ghidra_cli::ghidra::{bridge, java};
use std::process::Command;
use std::time::Duration;

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
fn bridge_compiles_with_long_classpath_and_quoted_paths() {
    require_ghidra!();
    let config = ghidra_cli::config::Config::load().unwrap();
    let install = config.get_ghidra_install_dir().unwrap();
    let jdk = java::resolve_for_ghidra(&install, config.get_java_home()).unwrap();
    let root = tempfile::Builder::new()
        .prefix("javac classpath's #日本語 ")
        .tempdir()
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
    for entry in walkdir::WalkDir::new(&install) {
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

    bridge::compile_check(&jars, &jdk.home).unwrap_or_else(|error| panic!("{error}"));
}
