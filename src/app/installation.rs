use super::project::load_config;
use crate::cli::{Cli, Commands};
use crate::config::Config;
use crate::ghidra::{self, GhidraClient};
use std::path::PathBuf;

/// Handle the setup command - download and install Ghidra.
pub(crate) async fn run_setup(cli: Cli) -> anyhow::Result<()> {
    let args = match cli.command {
        Commands::Setup(args) => args,
        _ => unreachable!(),
    };

    println!("Ghidra Setup Wizard");
    println!("===================\n");

    // 1. Check Java — Ghidra needs a full JDK (not a JRE) to compile scripts.
    if !args.force {
        let explicit = Config::load().ok().and_then(|c| c.get_java_home());
        match ghidra::java::resolve_jdk(explicit.as_deref(), ghidra::java::DEFAULT_MIN_JAVA) {
            ghidra::java::JavaStatus::Ok(info) => {
                println!(
                    "✓ JDK {} found at {} (via {})",
                    info.major,
                    info.home.display(),
                    info.source
                );
            }
            other => {
                eprintln!(
                    "Java prerequisite check failed: {}",
                    ghidra::java::describe_failure(&other)
                );
                eprintln!("Use --force to continue anyway.");
                std::process::exit(1);
            }
        }
    } else {
        println!("Skipping Java check (--force specified)");
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
    println!("\nInstalling to: {}", install_base.display());
    let final_path = ghidra::setup::install_ghidra(args.version, install_base).await?;

    // 4. Update Config
    let mut config = Config::load()?;
    config.ghidra_install_dir = Some(final_path.clone());
    config.save()?;

    println!("\nSuccess! Ghidra installed at: {}", final_path.display());
    println!("Configuration updated.");

    // 5. Verify
    println!("\nVerifying installation...");
    let client = GhidraClient::new(config)?;
    if client.verify_installation().is_ok() {
        println!("Verification passed!");
        println!("\nYou can now run: ghidra import <binary> --project <name>");
    } else {
        println!("Verification failed - analyzeHeadless not found");
        println!("  The installation may be incomplete.");
    }

    Ok(())
}

pub(super) fn handle_doctor(projects_dir: &Option<PathBuf>) -> anyhow::Result<()> {
    println!("Ghidra CLI Doctor");
    println!("=================\n");

    let config = load_config(projects_dir)?;

    // Check Ghidra installation
    print!("Checking Ghidra installation... ");
    match config.get_ghidra_install_dir() {
        Ok(dir) => {
            println!("OK");
            println!("  Location: {}", dir.display());

            let client = GhidraClient::new(config.clone());
            match client {
                Ok(c) => {
                    if c.verify_installation().is_ok() {
                        println!("  analyzeHeadless: OK");
                    } else {
                        println!("  analyzeHeadless: NOT FOUND");
                    }
                }
                Err(e) => {
                    println!("  Error: {}", e);
                }
            }
        }
        Err(e) => {
            println!("FAILED");
            println!("  Error: {}", e);
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

    print!("\nChecking Java (full JDK {}+)... ", min);
    match ghidra::java::resolve_jdk(explicit.as_deref(), min) {
        JavaStatus::Ok(info) => {
            println!("OK");
            println!(
                "  JDK {} at {} (selected via {})",
                info.major,
                info.home.display(),
                info.source
            );

            // Real health check: compile the embedded bridge script against the
            // installed Ghidra. Catches API incompatibilities and JRE issues.
            if let Some(install) = &install_dir {
                print!("\nChecking bridge script compiles... ");
                match ghidra::bridge::compile_check(install, &info.home) {
                    Ok(()) => println!("OK"),
                    Err(errs) => {
                        println!("FAILED");
                        for line in errs.lines() {
                            println!("  {}", line);
                        }
                    }
                }
            }
        }
        JavaStatus::JreNoCompiler { home, major } => {
            println!("FAILED");
            println!(
                "  JRE detected: Java {} at {} has no javac / jdk.compiler module.",
                major,
                home.display()
            );
            println!(
                "  Ghidra requires a full JDK {}+ to compile scripts (a JRE cannot work).",
                min
            );
            println!("  Install a JDK, or select one with --java-home / GHIDRA_CLI_JAVA_HOME / config `java_home`.");
        }
        JavaStatus::WrongVersion { home, major, min } => {
            println!("FAILED");
            println!(
                "  JDK {} at {} is below the required JDK {}+.",
                major,
                home.display(),
                min
            );
        }
        JavaStatus::NotFound => {
            println!("FAILED");
            println!(
                "  No Java found. Install a full JDK {}+ or set --java-home.",
                min
            );
        }
    }

    // Check project directory
    print!("\nChecking project directory... ");
    match config.get_project_dir() {
        Ok(dir) => {
            println!("OK");
            println!("  Location: {}", dir.display());
            println!(
                "  Exists: {}",
                if dir.exists() {
                    "yes"
                } else {
                    "no (will be created)"
                }
            );
        }
        Err(e) => {
            println!("FAILED");
            println!("  Error: {}", e);
        }
    }

    // Check config file
    print!("\nConfig file... ");
    match Config::config_path() {
        Ok(path) => {
            println!("OK");
            println!("  Location: {}", path.display());
            println!("  Exists: {}", if path.exists() { "yes" } else { "no" });
        }
        Err(e) => {
            println!("FAILED");
            println!("  Error: {}", e);
        }
    }

    println!("\nScript execution modes:");
    println!("  `ghidra script run PATH`  — compiles & runs a file on disk");
    println!("  `ghidra script run -`     — reads Java source from stdin for one-offs;");
    println!(
        "                              staged to a temp file, same compile/execute path as PATH"
    );
    println!("  `ghidra script python/java <code>` — disabled by design, not a bug: every script,");
    println!(
        "                              including one-offs, is required to go through Ghidra's"
    );
    println!(
        "                              normal script bundle/compile gate rather than a second,"
    );
    println!("                              less-sandboxed eval path. Use `script run -` instead.");

    println!("\nDone!");
    Ok(())
}
