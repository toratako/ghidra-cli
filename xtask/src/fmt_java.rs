//! Run the pinned Google Java formatter on repository Java sources.

use anyhow::{bail, ensure, Context, Result};
use ghidra_cli::ghidra::java::{resolve_jdk, JavaStatus};
use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, ExitStatus};
use walkdir::WalkDir;

const JAR_NAME: &str = "google-java-format-1.37.0-all-deps.jar";
const DOWNLOAD_URL: &str = "https://github.com/google/google-java-format/releases/download/v1.37.0/google-java-format-1.37.0-all-deps.jar";
const SHA256: &str = "834b2a0c38cb774953322a84b5ca3f2f40dd3156650b3cd44d3b744345962f7a";
const MAX_BATCH_FILES: usize = 24;
const MAX_COMMAND_UNITS: usize = 24_000;

pub(crate) fn run(root: &Path, check: bool) -> Result<ExitCode> {
    let root = std::path::absolute(root).context("failed to resolve the workspace root")?;
    let sources = collect_sources(&root)?;
    if sources.is_empty() {
        return Ok(ExitCode::SUCCESS);
    }
    let home = match resolve_jdk(None, 21) {
        JavaStatus::Ok(info) => info.home,
        JavaStatus::JreNoCompiler { home, major } => bail!(
            "Java {major} at {} is not a full JDK; install JDK 21+ and set JAVA_HOME or PATH",
            home.display()
        ),
        JavaStatus::WrongVersion { home, major, min } => bail!(
            "JDK {major} at {} is too old; install JDK {min}+ and set JAVA_HOME or PATH",
            home.display()
        ),
        JavaStatus::NotFound => {
            bail!("JDK 21+ was not found; install it and set JAVA_HOME or PATH")
        }
    };
    let java = home
        .join("bin")
        .join(if cfg!(windows) { "java.exe" } else { "java" });
    let jar = cached_jar(&root, SHA256, download)?;
    format_sources(&root, &java, &jar, &sources, check, |command| {
        command.status().context("failed to run google-java-format")
    })
}

fn collect_sources(root: &Path) -> Result<Vec<PathBuf>> {
    let mut sources = Vec::new();
    for directory in [root.join("src"), root.join("tests")] {
        for entry in WalkDir::new(&directory) {
            let entry = entry.with_context(|| {
                format!("failed to find Java sources in {}", directory.display())
            })?;
            // Do not follow symlinks or include .java.in/.java.inc fragments.
            if entry.file_type().is_file() && entry.path().extension() == Some(OsStr::new("java")) {
                sources.push(entry.path().strip_prefix(root)?.to_path_buf());
            }
        }
    }
    sources.sort();
    Ok(sources)
}

fn cached_jar(
    root: &Path,
    expected_sha256: &str,
    download: impl FnOnce(&Path) -> Result<()>,
) -> Result<PathBuf> {
    let cache = root.join("target").join("google-java-format");
    fs::create_dir_all(&cache).with_context(|| format!("failed to create {}", cache.display()))?;
    let lock_path = cache.join("download.lock");
    // Keep the lock file: unlinking it can give parallel callers different locks.
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .with_context(|| format!("failed to open {}", lock_path.display()))?;
    lock.lock()
        .with_context(|| format!("failed to lock {}", lock_path.display()))?;

    let jar = cache.join(JAR_NAME);
    match fs::metadata(&jar) {
        Ok(_) => {
            verify_jar(&jar, expected_sha256).with_context(|| {
                format!(
                    "remove {} and retry to download a fresh formatter",
                    jar.display()
                )
            })?;
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {
            let staging = tempfile::Builder::new()
                .prefix(".download-")
                .tempdir_in(&cache)
                .context("failed to create formatter download directory")?;
            let pending = staging.path().join(JAR_NAME);
            download(&pending)?;
            verify_jar(&pending, expected_sha256)?;
            // The staging directory is on the cache filesystem. Publish only
            // after curl exits and the complete download passes verification.
            fs::rename(&pending, &jar)
                .with_context(|| format!("failed to publish {}", jar.display()))?;
        }
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", jar.display()));
        }
    }
    Ok(jar)
}

fn verify_jar(path: &Path, expected_sha256: &str) -> Result<()> {
    let mut file = File::open(path)
        .with_context(|| format!("failed to open formatter JAR {}", path.display()))?;
    let mut digest = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .with_context(|| format!("failed to read formatter JAR {}", path.display()))?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    let actual: String = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    ensure!(
        actual == expected_sha256,
        "formatter JAR SHA-256 mismatch for {}: expected {expected_sha256}, got {actual}",
        path.display()
    );
    Ok(())
}

fn download(path: &Path) -> Result<()> {
    let status = Command::new("curl")
        .args(["--fail", "--location", "--retry", "3", "--output"])
        .arg(path)
        .arg(DOWNLOAD_URL)
        .status()
        .context("failed to download google-java-format; curl must be available on PATH")?;
    ensure!(status.success(), "formatter download failed: {status}");
    Ok(())
}

fn format_sources(
    root: &Path,
    java: &Path,
    jar: &Path,
    sources: &[PathBuf],
    check: bool,
    mut execute: impl FnMut(&mut Command) -> Result<ExitStatus>,
) -> Result<ExitCode> {
    let mut offset = 0;
    while offset < sources.len() {
        let mut command = Command::new(java);
        command
            .current_dir(root)
            .arg("-jar")
            .arg(jar)
            // Keep string spellings used by source-based failure probes intact.
            .arg("--skip-reflowing-long-strings");
        if check {
            command.args(["--dry-run", "--set-exit-if-changed"]);
        } else {
            command.arg("--replace");
        }
        let mut units = argument_units(command.get_program())
            + command.get_args().map(argument_units).sum::<usize>();
        let mut end = offset;
        while end < sources.len() && end - offset < MAX_BATCH_FILES {
            let next = argument_units(sources[end].as_os_str());
            if units.saturating_add(next) > MAX_COMMAND_UNITS {
                ensure!(
                    end > offset,
                    "formatter command line is too long for {}",
                    sources[end].display()
                );
                break;
            }
            command.arg(&sources[end]);
            units += next;
            end += 1;
        }
        // Inherit formatter output, including dry-run filenames and parse errors.
        // Stop on any failure before proceeding to another batch.
        if !execute(&mut command)?.success() {
            return Ok(ExitCode::FAILURE);
        }
        offset = end;
    }
    Ok(ExitCode::SUCCESS)
}

fn argument_units(argument: &OsStr) -> usize {
    // Conservatively allow two units per encoded byte plus quotes/separators,
    // covering Windows UTF-16 and escaped quotes/backslashes under its 32K limit.
    argument.as_encoded_bytes().len().saturating_mul(2) + 3
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    const TEST_JAR: &[u8] = b"verified formatter fixture";
    const TEST_SHA256: &str = "f33b8ca26daae25933ceef4a79631b9a0bed6b8cc2c77f235398f0fa4d21656d";
    const CHILD_EXIT: &str = "XTASK_FMT_JAVA_CHILD_EXIT";

    fn workspace() -> tempfile::TempDir {
        let root = tempfile::Builder::new()
            .prefix("Java formatter's ")
            .tempdir()
            .unwrap();
        fs::create_dir(root.path().join("src")).unwrap();
        fs::create_dir(root.path().join("tests")).unwrap();
        root
    }

    fn cached_path(root: &Path) -> PathBuf {
        root.join("target")
            .join("google-java-format")
            .join(JAR_NAME)
    }

    #[test]
    fn source_scope_is_recursive_regular_java_only_and_sorted() {
        let root = workspace();
        for relative in [
            "tests/fixtures/z/Last.java",
            "src/first/First.java",
            "tests/fixtures/Template.java.in",
            "tests/fixtures/Fragment.java.inc",
            "src/other/UPPER.JAVA",
            "docs/local/Ignored.java",
        ] {
            let path = root.path().join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, []).unwrap();
        }
        fs::create_dir(root.path().join("src").join("Directory.java")).unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(
                root.path().join("src/first/First.java"),
                root.path().join("src/Alias.java"),
            )
            .unwrap();
            std::os::unix::fs::symlink(
                root.path().join("docs/local"),
                root.path().join("src/external"),
            )
            .unwrap();
        }

        assert_eq!(
            collect_sources(root.path()).unwrap(),
            [
                PathBuf::from("src").join("first").join("First.java"),
                PathBuf::from("tests")
                    .join("fixtures")
                    .join("z")
                    .join("Last.java"),
            ]
        );
    }

    #[test]
    fn cache_publishes_verified_download_and_verifies_it_again_before_reuse() {
        let root = workspace();
        let jar = cached_jar(root.path(), TEST_SHA256, |pending| {
            assert!(!cached_path(root.path()).exists());
            let lock = OpenOptions::new().read(true).write(true).open(
                pending
                    .parent()
                    .unwrap()
                    .parent()
                    .unwrap()
                    .join("download.lock"),
            )?;
            assert!(matches!(lock.try_lock(), Err(fs::TryLockError::WouldBlock)));
            fs::write(pending, TEST_JAR)?;
            Ok(())
        })
        .unwrap();
        assert_eq!(fs::read(&jar).unwrap(), TEST_JAR);
        assert_eq!(
            cached_jar(root.path(), TEST_SHA256, |_| panic!("cache must be reused")).unwrap(),
            jar
        );

        fs::write(&jar, b"corrupt cache").unwrap();
        let error = cached_jar(root.path(), TEST_SHA256, |_| {
            panic!("corrupt cache must fail before a JAR is returned")
        })
        .unwrap_err();
        assert!(format!("{error:#}").contains("SHA-256 mismatch"));
        assert!(error.to_string().contains("remove"));
    }

    #[test]
    fn failed_or_corrupt_downloads_never_publish_a_cached_jar() {
        for fail_download in [true, false] {
            let root = workspace();
            let result = cached_jar(root.path(), TEST_SHA256, |pending| {
                fs::write(pending, b"incomplete download")?;
                if fail_download {
                    bail!("download interrupted");
                }
                Ok(())
            });
            let error = result.unwrap_err();
            assert!(
                error.to_string().contains(if fail_download {
                    "download interrupted"
                } else {
                    "SHA-256 mismatch"
                }),
                "{error:#}"
            );
            let jar = cached_path(root.path());
            assert!(!jar.exists());
            assert_eq!(fs::read_dir(jar.parent().unwrap()).unwrap().count(), 1);
        }
    }

    #[test]
    fn formatter_child() {
        if let Some(exit) = std::env::var_os(CHILD_EXIT) {
            std::process::exit(exit.to_str().unwrap().parse().unwrap());
        }
    }

    fn child_status(exit: u8) -> ExitStatus {
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "fmt_java::tests::formatter_child"])
            .env(CHILD_EXIT, exit.to_string())
            .status()
            .unwrap()
    }

    #[test]
    fn formatter_preserves_paths_and_batches_without_shell_interpretation() {
        let root = workspace();
        let java = root.path().join("JDK's directory").join("bin").join("java");
        let jar = cached_path(root.path());
        let mut sources = vec![PathBuf::from("src").join("space ' quote \\ slash 日本語.java")];
        sources.extend(
            (0..MAX_BATCH_FILES)
                .map(|index| PathBuf::from("tests").join(format!("Fixture{index}.java"))),
        );
        let success = child_status(0);

        for check in [false, true] {
            let mut batches = Vec::new();
            let result = format_sources(root.path(), &java, &jar, &sources, check, |command| {
                assert_eq!(command.get_program(), java.as_os_str());
                assert_eq!(command.get_current_dir(), Some(root.path()));
                let arguments: Vec<_> = command.get_args().map(OsStr::to_owned).collect();
                let mut expected: Vec<OsString> = vec![
                    "-jar".into(),
                    jar.as_os_str().to_owned(),
                    "--skip-reflowing-long-strings".into(),
                ];
                if check {
                    expected.extend(["--dry-run".into(), "--set-exit-if-changed".into()]);
                } else {
                    expected.push("--replace".into());
                }
                assert_eq!(arguments[..expected.len()], expected);
                batches.push(arguments[expected.len()..].to_vec());
                Ok(success)
            })
            .unwrap();
            assert_eq!(result, ExitCode::SUCCESS);
            assert_eq!(batches.iter().map(Vec::len).collect::<Vec<_>>(), [24, 1]);
            assert_eq!(
                batches.into_iter().flatten().collect::<Vec<_>>(),
                sources
                    .iter()
                    .map(|path| path.as_os_str().to_owned())
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn formatter_respects_command_size_and_stops_on_child_failure() {
        let root = workspace();
        let jar = cached_path(root.path());
        let java = root.path().join("java");
        let sources = vec![PathBuf::from(format!("src/{}.java", "x".repeat(6_000))); 3];
        let success = child_status(0);
        let mut calls = 0;
        assert_eq!(
            format_sources(root.path(), &java, &jar, &sources, true, |_| {
                calls += 1;
                Ok(success)
            })
            .unwrap(),
            ExitCode::SUCCESS
        );
        assert_eq!(
            calls, 3,
            "character bounds must apply before the file count limit"
        );

        let failure = child_status(7);
        for check in [false, true] {
            let mut calls = 0;
            assert_eq!(
                format_sources(root.path(), &java, &jar, &sources, check, |_| {
                    calls += 1;
                    Ok(failure)
                })
                .unwrap(),
                ExitCode::FAILURE
            );
            assert_eq!(calls, 1, "do not continue after parse/runtime errors");
        }
        assert!(
            format_sources(root.path(), &java, &jar, &sources, true, |_| {
                bail!("could not launch Java")
            })
            .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn formatter_signal_exit_is_a_failure() {
        use std::os::unix::process::ExitStatusExt;

        let root = workspace();
        assert_eq!(
            format_sources(
                root.path(),
                Path::new("java"),
                &cached_path(root.path()),
                &[PathBuf::from("src/Test.java")],
                true,
                |_| Ok(ExitStatus::from_raw(9)),
            )
            .unwrap(),
            ExitCode::FAILURE
        );
    }
}
