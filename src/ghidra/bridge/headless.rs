//! Headless command construction, Java selection, and compile diagnostics.

use super::sources;
use crate::ghidra::installation::{Installation, InstallationKind};
use crate::ghidra::java::{self, JdkInfo};
use anyhow::Result;
use std::ffi::OsString;
use std::path::Path;
use std::process::Command;
use tracing::{info, warn};

/// Both persistent and one-shot workflows use the selected installation.
/// Directory launches retain Ghidra's own Java discovery as a last resort;
/// a standalone JAR has no LaunchSupport wrapper and needs a resolved full JDK.
pub(super) fn headless_command(installation: &Installation) -> Result<Command> {
    let explicit_java = crate::config::Config::load()?.get_java_home();
    let jdk = match java::resolve_for_ghidra(installation, explicit_java) {
        Ok(jdk) => {
            info!(
                "Using JDK {} at {} ({})",
                jdk.major,
                jdk.home.display(),
                jdk.source
            );
            Some(jdk)
        }
        Err(e) if installation.kind == InstallationKind::Directory => {
            warn!(
                "No suitable JDK auto-selected; letting Ghidra choose. {}",
                e
            );
            None
        }
        Err(e) => anyhow::bail!(e),
    };
    command_with_jdk(
        installation,
        jdk.as_ref(),
        std::env::var_os("GHIDRA_HEADLESS_MAXMEM"),
        std::env::var_os("GHIDRA_MAXMEM"),
    )
}

fn command_with_jdk(
    installation: &Installation,
    jdk: Option<&JdkInfo>,
    headless_maxmem: Option<OsString>,
    maxmem: Option<OsString>,
) -> Result<Command> {
    let mut cmd = match installation.kind {
        InstallationKind::Directory => {
            Command::new(installation.launcher().expect("directory launcher"))
        }
        InstallationKind::Jar => {
            let jdk = jdk
                .ok_or_else(|| anyhow::anyhow!("A full JDK is required to launch a Ghidra JAR"))?;
            let java = jdk
                .home
                .join("bin")
                .join(if cfg!(windows) { "java.exe" } else { "java" });
            let heap = headless_maxmem
                .filter(|value| !value.is_empty())
                .or_else(|| maxmem.filter(|value| !value.is_empty()))
                .unwrap_or_else(|| "2G".into());
            let mut max_heap = OsString::from("-Xmx");
            max_heap.push(heap);
            let mut command = Command::new(java);
            // Headless defaults from the official analyzeHeadless and
            // launch.properties. JarRun supplies its own application layout;
            // it does not need Ghidra's distribution class loader.
            command.arg(max_heap).args([
                "-XX:ParallelGCThreads=2",
                "-XX:CICompilerCount=2",
                "-Djava.awt.headless=true",
                "-Dfile.encoding=UTF8",
                "-Duser.country=US",
                "-Duser.language=en",
                "-Duser.variant=",
                "-Djavax.xml.accessExternalDTD=",
                "-Djavax.xml.accessExternalSchema=",
                "-Djavax.xml.accessExternalStylesheet=",
                "--enable-native-access=ALL-UNNAMED",
            ]);
            #[cfg(windows)]
            command.arg("-Dlog4j.skipJansi=true");
            command.arg("-jar").arg(&installation.path);
            command
        }
    };
    if let Some(jdk) = jdk {
        cmd.env("JAVA_HOME", &jdk.home);
    }
    Ok(cmd)
}

/// Compile the embedded bridge script with the given JDK against the Ghidra
/// install's jars, to verify it actually compiles (catches JRE-vs-JDK problems
/// and Ghidra API incompatibilities). Returns the javac error lines on failure.
pub fn compile_check(
    installation: &Installation,
    jdk_home: &Path,
) -> std::result::Result<(), String> {
    let javac_name = if cfg!(windows) { "javac.exe" } else { "javac" };

    // Resolve caller-relative paths before changing the compiler's directory.
    let javac = std::path::absolute(jdk_home.join("bin").join(javac_name))
        .map_err(|e| format!("Failed to resolve javac path: {e}"))?;
    if !javac.exists() {
        return Err(format!("javac not found at {}", javac.display()));
    }

    let tmp = tempfile::tempdir().map_err(|e| e.to_string())?;
    let source_dir = tmp.path().join("sources");
    let sources = sources::write_to(&source_dir).map_err(|e| e.to_string())?;

    let classpath = compile_classpath(installation)?;

    // The classpath and source paths together can exceed Windows' command-line
    // limit. Keep them in a javac argument file on every platform.
    let mut arguments = String::new();
    for argument in [
        "-proc:none",
        "-cp",
        &classpath.to_string_lossy(),
        "-d",
        &tmp.path().join("out").to_string_lossy(),
        "-sourcepath",
        &source_dir.to_string_lossy(),
    ] {
        append_javac_argument(&mut arguments, argument);
    }
    for source in &sources {
        append_javac_argument(&mut arguments, &source.to_string_lossy());
    }
    let argument_file = tmp.path().join("javac.args");
    std::fs::write(&argument_file, arguments)
        .map_err(|e| format!("Failed to write javac argument file: {e}"))?;
    // Windows javac can lose characters outside the system code page in argv.
    // Pass only an ASCII filename; Unicode paths stay in the UTF-8 argument file.
    let out = Command::new(&javac)
        .current_dir(tmp.path())
        .arg("@javac.args")
        .output()
        .map_err(|e| format!("Failed to run javac: {}", e))?;

    if out.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let errs: Vec<&str> = stderr
            .lines()
            .filter(|l| {
                l.contains("error:")
                    || l.trim_start().starts_with("symbol:")
                    || l.trim_start().starts_with("location:")
            })
            .collect();
        if errs.is_empty() {
            Err(stderr.lines().take(20).collect::<Vec<_>>().join("\n"))
        } else {
            Err(errs.join("\n"))
        }
    }
}

fn compile_classpath(installation: &Installation) -> std::result::Result<OsString, String> {
    let path = std::path::absolute(&installation.path)
        .map_err(|e| format!("Failed to resolve Ghidra path: {e}"))?;
    let jars = match installation.kind {
        InstallationKind::Jar => vec![path],
        InstallationKind::Directory => {
            let mut jars = Vec::new();
            for entry in walkdir::WalkDir::new(path) {
                let entry = entry.map_err(|e| format!("Failed to find Ghidra libraries: {e}"))?;
                if entry.path().is_file()
                    && entry.path().extension().is_some_and(|ext| ext == "jar")
                {
                    jars.push(entry.into_path());
                }
            }
            jars
        }
    };
    if jars.is_empty() {
        return Err("No Ghidra jars found to compile against".to_string());
    }
    std::env::join_paths(jars).map_err(|e| format!("Invalid Ghidra classpath: {e}"))
}

fn append_javac_argument(arguments: &mut String, value: &str) {
    // javac's argument-file parser interprets backslash escapes inside quotes.
    arguments.push('"');
    for character in value.chars() {
        match character {
            '\\' => arguments.push_str("\\\\"),
            '"' => arguments.push_str("\\\""),
            '\n' => arguments.push_str("\\n"),
            '\r' => arguments.push_str("\\r"),
            _ => arguments.push(character),
        }
    }
    arguments.push_str("\"\n");
}

/// Detect the OSGi script compile/load failure signature in Ghidra output and
/// return an actionable hint (empty string if the failure looks unrelated).
pub(super) fn bridge_failure_hint(output: &str) -> String {
    let osgi_fail = output.contains("Failed to get OSGi bundle")
        || output.contains("GhidraScriptLoadException")
        || (output.contains("ClassNotFoundException") && output.contains("GhidraCliBridge"));
    if osgi_fail {
        "\n\nThe Ghidra bridge script failed to compile/load. Common causes:\n  \
         - The Java Ghidra used is a JRE without a compiler (no `javac` / `jdk.compiler` module).\n  \
         - A Ghidra API incompatibility in the bridge script.\n\
         Run `ghidra-cli doctor` to diagnose: it verifies a full JDK and compiles the bridge to show the real error."
            .to_string()
    } else {
        String::new()
    }
}

#[cfg(test)]
mod tests;
