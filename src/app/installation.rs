use super::output::Output;
use super::project::load_config;
use crate::ghidra;
use serde_json::json;
use std::path::PathBuf;

pub(super) fn handle_doctor(
    projects_dir: &Option<PathBuf>,
    runtime: bool,
    output: Output,
) -> anyhow::Result<()> {
    use std::fmt::Write;
    let mut report = String::new();
    let mut failures = Vec::new();
    writeln!(report, "Ghidra CLI Doctor")?;
    writeln!(report, "=================\n")?;

    let config = load_config(projects_dir)?;

    // Check Ghidra installation
    write!(report, "Checking Ghidra installation... ")?;
    let (installation, selected) = match ghidra::installation::resolve(&config) {
        Ok(installation) => {
            writeln!(report, "OK")?;
            writeln!(report, "  Location: {}", installation.path.display())?;
            writeln!(report, "  Source: {}", installation.source)?;
            writeln!(report, "  Version: {}", installation.version)?;
            let (kind, launcher) = match installation.kind {
                ghidra::installation::InstallationKind::Directory => {
                    ("directory", "analyzeHeadless")
                }
                ghidra::installation::InstallationKind::Jar => ("jar", "java -jar"),
            };
            writeln!(report, "  Format: {kind}")?;
            writeln!(report, "  Headless launcher: OK ({launcher})")?;
            let mut detail = serde_json::to_value(&installation)?;
            detail["ok"] = json!(true);
            (detail, Some(installation))
        }
        Err(e) => {
            failures.push(e.to_string());
            writeln!(report, "FAILED")?;
            writeln!(report, "  Error: {}", e)?;
            let message = e.to_string();
            (
                json!({"ok": false, "message": message, "detail": crate::error::diagnostic_detail(&e.into())}),
                None,
            )
        }
    };

    // Check Java — must be a full JDK (Ghidra compiles scripts at runtime).
    use ghidra::java::JavaStatus;
    let min = selected
        .as_ref()
        .map(|installation| installation.min_java)
        .unwrap_or(ghidra::java::DEFAULT_MIN_JAVA);
    let explicit = config.get_java_home();

    write!(report, "\nChecking Java (full JDK {}+)... ", min)?;
    match ghidra::java::resolve_jdk(explicit.as_deref(), min) {
        JavaStatus::Ok(info) => {
            writeln!(report, "OK")?;
            writeln!(
                report,
                "  JDK {} at {} (selected via {})",
                info.major,
                info.home.display(),
                info.source
            )?;

            // Real health check: compile the embedded bridge script against the
            // installed Ghidra. Catches API incompatibilities and JRE issues.
            if let Some(install) = &selected {
                write!(report, "\nChecking bridge script compiles... ")?;
                match ghidra::bridge::compile_check(install, &info.home) {
                    Ok(()) => writeln!(report, "OK")?,
                    Err(errs) => {
                        failures.push(format!("Bridge compilation failed: {errs}"));
                        writeln!(report, "FAILED")?;
                        for line in errs.lines() {
                            writeln!(report, "  {}", line)?;
                        }
                    }
                }
            }
        }
        JavaStatus::JreNoCompiler { home, major } => {
            failures.push("Java is a JRE; install a full JDK".to_string());
            writeln!(report, "FAILED")?;
            writeln!(
                report,
                "  JRE detected: Java {} at {} has no javac / jdk.compiler module.",
                major,
                home.display()
            )?;
            writeln!(
                report,
                "  Ghidra requires a full JDK {}+ to compile scripts (a JRE cannot work).",
                min
            )?;
            writeln!(report, "  Install a JDK, or select one with --java-home / GHIDRA_CLI_JAVA_HOME / config `java_home`.")?;
        }
        JavaStatus::WrongVersion { home, major, min } => {
            failures.push(format!("Java {major} is below required JDK {min}"));
            writeln!(report, "FAILED")?;
            writeln!(
                report,
                "  JDK {} at {} is below the required JDK {}+.",
                major,
                home.display(),
                min
            )?;
        }
        JavaStatus::NotFound => {
            failures.push("No Java found; install a full JDK".to_string());
            writeln!(report, "FAILED")?;
            writeln!(
                report,
                "  No Java found. Install a full JDK {}+ or set --java-home.",
                min
            )?;
        }
    }

    let storage = ghidra::bridge::diagnostics::storage_checks(&config);
    writeln!(
        report,
        "\nChecking storage (create, write, rename, delete)..."
    )?;
    for check in &storage {
        let ok = check["ok"] == true;
        writeln!(
            report,
            "  {}: {} — {}",
            check["name"].as_str().unwrap(),
            if ok { "OK" } else { "FAILED" },
            check["path"].as_str().unwrap_or("unresolved")
        )?;
        writeln!(report, "    Source: {}", check["source"].as_str().unwrap())?;
        if !ok {
            let message = check["message"].as_str().unwrap_or("Storage check failed");
            failures.push(message.to_owned());
            writeln!(report, "    {message}")?;
        }
    }
    let loopback = match ghidra::bridge::diagnostics::loopback_check() {
        Ok(()) => {
            writeln!(report, "\nLoopback TCP bind/connect: OK")?;
            json!({"ok": true})
        }
        Err(error) => {
            let message = format!("{error:#}");
            failures.push(message.clone());
            writeln!(report, "\nLoopback TCP bind/connect: FAILED — {message}")?;
            json!({"ok": false, "message": message})
        }
    };
    let runtime_check = if !runtime {
        writeln!(report, "\nGhidra runtime: NOT CHECKED (use doctor --runtime for settings/cache writes, OSGi, and JVM bridge startup)")?;
        json!({"status": "not_checked"})
    } else if !failures.is_empty() {
        writeln!(
            report,
            "\nGhidra runtime: NOT CHECKED (resolve prerequisite failures first)"
        )?;
        json!({"status": "not_checked", "reason": "prerequisite_failure"})
    } else {
        match ghidra::bridge::diagnostics::runtime_check(
            &config,
            selected.as_ref().expect("validated installation"),
        ) {
            Ok(paths) => {
                writeln!(report, "\nGhidra runtime: OK (start, ping, shutdown)")?;
                writeln!(
                    report,
                    "  Ghidra settings: {}\n  Ghidra cache: {}",
                    paths["ghidra_settings"].as_str().unwrap_or("unknown"),
                    paths["ghidra_cache"].as_str().unwrap_or("unknown")
                )?;
                json!({"status": "success", "paths": paths})
            }
            Err(error) => {
                let message = format!("{error:#}");
                failures.push(message.clone());
                writeln!(report, "\nGhidra runtime: FAILED — {message}")?;
                json!({"status": "error", "message": message, "detail": crate::error::diagnostic_detail(&error)})
            }
        }
    };

    writeln!(report, "\nScript execution modes:")?;
    writeln!(
        report,
        "  `ghidra-cli script run PATH`  — compiles & runs a file on disk"
    )?;
    writeln!(
        report,
        "  `ghidra-cli script run -`     — reads Java source from stdin for one-offs;"
    )?;
    writeln!(
        report,
        "                              staged to a temp file, same compile/execute path as PATH"
    )?;

    writeln!(report, "\nDone!")?;
    output.result(&json!({"name": "Ghidra CLI Doctor", "ok": failures.is_empty(), "installation": installation, "failures": failures, "storage": storage, "loopback": loopback, "runtime": runtime_check, "report": report}), report.trim_end())?;
    anyhow::ensure!(
        failures.is_empty(),
        "Doctor found problems: {}",
        failures.join("; ")
    );
    Ok(())
}
