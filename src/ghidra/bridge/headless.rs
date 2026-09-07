//! Headless launcher discovery, Java environment selection, and compile diagnostics.

use super::JAVA_BRIDGE_SCRIPT;
use anyhow::Result;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{info, warn};

/// Select a full JDK for Ghidra and set `JAVA_HOME` on the command. Ghidra
/// compiles the bridge script at runtime via OSGi and needs javac/jdk.compiler,
/// which a JRE lacks. Setting `JAVA_HOME` on the child overrides Ghidra's
/// PATH-based auto-pick (honored by Ghidra's LaunchSupport on all platforms).
/// If we can't find a JDK, proceed and let Ghidra try — the readiness failure
/// path surfaces an actionable hint.
pub(super) fn apply_java_home(cmd: &mut Command, ghidra_install_dir: &Path) {
    let explicit_java = crate::config::Config::load()
        .ok()
        .and_then(|c| c.get_java_home());
    match crate::ghidra::java::resolve_for_ghidra(ghidra_install_dir, explicit_java) {
        Ok(jdk) => {
            info!(
                "Using JDK {} at {} ({})",
                jdk.major,
                jdk.home.display(),
                jdk.source
            );
            cmd.env("JAVA_HOME", &jdk.home);
        }
        Err(e) => {
            warn!(
                "No suitable JDK auto-selected; letting Ghidra choose. {}",
                e
            );
        }
    }
}

/// Compile the embedded bridge script with the given JDK against the Ghidra
/// install's jars, to verify it actually compiles (catches JRE-vs-JDK problems
/// and Ghidra API incompatibilities). Returns the javac error lines on failure.
pub fn compile_check(
    ghidra_install_dir: &Path,
    jdk_home: &Path,
) -> std::result::Result<(), String> {
    #[cfg(windows)]
    let (javac_name, cp_sep) = ("javac.exe", ';');
    #[cfg(not(windows))]
    let (javac_name, cp_sep) = ("javac", ':');

    let javac = jdk_home.join("bin").join(javac_name);
    if !javac.exists() {
        return Err(format!("javac not found at {}", javac.display()));
    }

    let tmp = tempfile::tempdir().map_err(|e| e.to_string())?;
    let src = tmp.path().join("GhidraCliBridge.java");
    std::fs::write(&src, JAVA_BRIDGE_SCRIPT).map_err(|e| e.to_string())?;

    let mut classpath = String::new();
    for entry in walkdir::WalkDir::new(ghidra_install_dir)
        .into_iter()
        .flatten()
    {
        if entry.path().extension().and_then(|e| e.to_str()) == Some("jar") {
            classpath.push_str(&entry.path().to_string_lossy());
            classpath.push(cp_sep);
        }
    }
    if classpath.is_empty() {
        return Err("No Ghidra jars found to compile against".to_string());
    }

    let out = std::process::Command::new(&javac)
        .arg("-proc:none")
        .arg("-cp")
        .arg(&classpath)
        .arg("-d")
        .arg(tmp.path().join("out"))
        .arg(&src)
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
         Run `ghidra doctor` to diagnose: it verifies a full JDK and compiles the bridge to show the real error."
            .to_string()
    } else {
        String::new()
    }
}

/// Find the analyzeHeadless script.
pub fn find_headless_script(ghidra_install_dir: &Path) -> Result<PathBuf> {
    let support_dir = ghidra_install_dir.join("support");

    #[cfg(unix)]
    let script_name = "analyzeHeadless";
    #[cfg(windows)]
    let script_name = "analyzeHeadless.bat";

    let script_path = support_dir.join(script_name);

    if script_path.exists() {
        Ok(script_path)
    } else {
        anyhow::bail!("analyzeHeadless not found at: {}", support_dir.display())
    }
}
