use super::output::Output;
use super::project::load_config;
use crate::cli::{Cli, Commands};
use crate::config::Config;
use crate::ghidra::{self, GhidraClient};
use serde_json::json;
use std::path::PathBuf;

/// Handle the setup command - download and install Ghidra.
pub(crate) async fn run_setup(cli: Cli) -> anyhow::Result<()> {
    let output = Output::new(&cli);
    let args = match cli.command {
        Commands::Setup(args) => args,
        _ => unreachable!(),
    };

    output.progress("Ghidra Setup Wizard");

    // 1. Check Java — Ghidra needs a full JDK (not a JRE) to compile scripts.
    if !args.force {
        let explicit = Config::load().ok().and_then(|c| c.get_java_home());
        match ghidra::java::resolve_jdk(explicit.as_deref(), ghidra::java::DEFAULT_MIN_JAVA) {
            ghidra::java::JavaStatus::Ok(info) => {
                output.progress(&format!(
                    "JDK {} found at {} (via {})",
                    info.major,
                    info.home.display(),
                    info.source
                ));
            }
            other => {
                anyhow::bail!(
                    "Java prerequisite check failed: {}. Use --force to continue anyway.",
                    ghidra::java::describe_failure(&other)
                );
            }
        }
    } else {
        output.progress("Skipping Java check (--force specified)");
    }

    // 2. Determine Install Directory
    let install_base = if let Some(d) = args.dir {
        PathBuf::from(d)
    } else {
        dirs::data_local_dir()
            .ok_or(anyhow::anyhow!("Could not determine data directory"))?
            .join("ghidra-cli")
            .join("ghidra")
    };

    std::fs::create_dir_all(&install_base)?;

    // 3. Install Ghidra
    output.progress(&format!("Installing to: {}", install_base.display()));
    let final_path =
        ghidra::setup::install_ghidra(args.version, install_base, output.quiet || output.json)
            .await?;

    // 4. Update Config
    let mut config = Config::load()?;
    config.ghidra_install_dir = Some(final_path.clone());
    config.save()?;

    // Report success only after the installed launcher has been verified.
    output.progress("Verifying installation...");
    verify_setup(&final_path)?;
    output.result(
        &json!({"installed": true, "path": final_path, "config_path": Config::config_path()?}),
        &format!(
            "Ghidra installed at: {}\nConfiguration updated. Verification passed!",
            final_path.display()
        ),
    )
}

fn verify_setup(path: &std::path::Path) -> anyhow::Result<()> {
    ghidra::bridge::find_headless_script(path).map(|_| ()).map_err(|err|
        anyhow::anyhow!("Installation verification failed: {err}. The installation may be incomplete; rerun 'ghidra setup'."))
}

pub(super) fn handle_doctor(projects_dir: &Option<PathBuf>, output: Output) -> anyhow::Result<()> {
    use std::fmt::Write;
    let mut report = String::new();
    let mut failures = Vec::new();
    writeln!(report, "Ghidra CLI Doctor")?;
    writeln!(report, "=================\n")?;

    let config = load_config(projects_dir)?;

    // Check Ghidra installation
    write!(report, "Checking Ghidra installation... ")?;
    match config.get_ghidra_install_dir() {
        Ok(dir) => {
            writeln!(report, "OK")?;
            writeln!(report, "  Location: {}", dir.display())?;

            let client = GhidraClient::new(config.clone());
            match client {
                Ok(c) => {
                    if c.verify_installation().is_ok() {
                        writeln!(report, "  analyzeHeadless: OK")?;
                    } else {
                        failures.push("analyzeHeadless not found".to_string());
                        writeln!(report, "  analyzeHeadless: NOT FOUND")?;
                    }
                }
                Err(e) => {
                    failures.push(e.to_string());
                    writeln!(report, "  Error: {}", e)?;
                }
            }
        }
        Err(e) => {
            failures.push(e.to_string());
            writeln!(report, "FAILED")?;
            writeln!(report, "  Error: {}", e)?;
        }
    }

    // Check Java
    // Check Java — must be a full JDK (Ghidra compiles scripts at runtime).
    use ghidra::java::JavaStatus;
    let install_dir = config.get_ghidra_install_dir().ok();
    let min = install_dir
        .as_deref()
        .map(ghidra::java::ghidra_min_java)
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
            if let Some(install) = &install_dir {
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

    // Check project directory
    write!(report, "\nChecking project directory... ")?;
    match config.get_project_dir() {
        Ok(dir) => {
            writeln!(report, "OK")?;
            writeln!(report, "  Location: {}", dir.display())?;
            writeln!(
                report,
                "  Exists: {}",
                if dir.exists() {
                    "yes"
                } else {
                    "no (will be created)"
                }
            )?;
        }
        Err(e) => {
            failures.push(e.to_string());
            writeln!(report, "FAILED")?;
            writeln!(report, "  Error: {}", e)?;
        }
    }

    // Check config file
    write!(report, "\nConfig file... ")?;
    match Config::config_path() {
        Ok(path) => {
            writeln!(report, "OK")?;
            writeln!(report, "  Location: {}", path.display())?;
            writeln!(
                report,
                "  Exists: {}",
                if path.exists() { "yes" } else { "no" }
            )?;
        }
        Err(e) => {
            failures.push(e.to_string());
            writeln!(report, "FAILED")?;
            writeln!(report, "  Error: {}", e)?;
        }
    }

    writeln!(report, "\nScript execution modes:")?;
    writeln!(
        report,
        "  `ghidra script run PATH`  — compiles & runs a file on disk"
    )?;
    writeln!(
        report,
        "  `ghidra script run -`     — reads Java source from stdin for one-offs;"
    )?;
    writeln!(
        report,
        "                              staged to a temp file, same compile/execute path as PATH"
    )?;
    writeln!(
        report,
        "  `ghidra script python/java <code>` — disabled by design, not a bug: every script,"
    )?;
    writeln!(
        report,
        "                              including one-offs, is required to go through Ghidra's"
    )?;
    writeln!(
        report,
        "                              normal script bundle/compile gate rather than a second,"
    )?;
    writeln!(
        report,
        "                              less-sandboxed eval path. Use `script run -` instead."
    )?;

    writeln!(report, "\nDone!")?;
    output.result(&json!({"name": "Ghidra CLI Doctor", "ok": failures.is_empty(), "failures": failures, "report": report}), report.trim_end())?;
    anyhow::ensure!(
        failures.is_empty(),
        "Doctor found problems: {}",
        failures.join("; ")
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_verification_rejects_missing_launcher() {
        let temp = tempfile::tempdir().unwrap();
        let error = verify_setup(temp.path()).unwrap_err().to_string();
        assert!(error.contains("verification failed"), "{error}");
    }
}
