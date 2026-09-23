//! Default official standalone JAR: detached launch, native tools and saved projects.
#[path = "support/json.rs"]
mod json_output;

#[macro_use]
mod common;

use ghidra_cli::ghidra::{bridge, installation::InstallationKind, java};
use ghidra_cli::ipc::client::BridgeClient;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

struct JarRuntime {
    root: tempfile::TempDir,
    jar: PathBuf,
    project: PathBuf,
    restored: PathBuf,
}

impl JarRuntime {
    fn new() -> Self {
        let config = ghidra_cli::config::Config::load().unwrap();
        let installation = config.get_ghidra_installation().unwrap();
        let jdk = java::resolve_for_ghidra(&installation, config.get_java_home()).unwrap();
        let root = tempfile::Builder::new()
            .prefix("standalone JAR ")
            .tempdir()
            .unwrap();
        let build = tempfile::Builder::new()
            .prefix("official-jar-build-")
            .tempdir()
            .unwrap();
        let source = match installation.kind {
            InstallationKind::Directory => {
                let builder = installation.path.join("support").join(if cfg!(windows) {
                    "buildGhidraJar.bat"
                } else {
                    "buildGhidraJar"
                });
                // Invoke the official script without module customizations.
                // Command handles the .bat launcher on Windows.
                let mut command = Command::new(builder);
                command
                    .current_dir(build.path())
                    .env("JAVA_HOME", &jdk.home)
                    .env("JAVA_HOME_OVERRIDE", &jdk.home);
                let output =
                    common::run_command_with_output(&mut command, Duration::from_secs(300))
                        .expect("run official buildGhidraJar");
                assert!(output.status.success(), "buildGhidraJar: {output:?}");
                build.path().join("ghidra.jar")
            }
            InstallationKind::Jar => installation.path,
        };
        // Ghidra project paths reject apostrophes and '#'; exercise these
        // supported runtime path characters in the detached JAR directory.
        let jar_directory = root.path().join("runtime's #日本語");
        std::fs::create_dir(&jar_directory).unwrap();
        let jar = jar_directory.join("ghidra 日本語.jar");
        std::fs::copy(source, &jar).expect("copy JAR outside the distribution/build directory");
        let jar = dunce::canonicalize(jar).unwrap();
        // Remove the build output before any runtime operation.
        drop(build);
        std::fs::write(
            root.path().join("config.yaml"),
            serde_yaml::to_string(&config).unwrap(),
        )
        .unwrap();
        std::fs::create_dir(root.path().join("tmp")).unwrap();
        Self {
            project: root.path().join("original project 日本語"),
            restored: root.path().join("restored project 日本語"),
            root,
            jar,
        }
    }

    fn run(&self, project: &Path, args: &[&str]) -> Value {
        let mut command = Command::new(assert_cmd::cargo::cargo_bin!("ghidra-cli"));
        let temporary = self.root.path().join("tmp");
        let mut java_options = std::env::var("JAVA_TOOL_OPTIONS").unwrap_or_default();
        for (property, path) in [
            (
                "application.settingsdir",
                self.root.path().join("ghidra-settings"),
            ),
            (
                "application.cachedir",
                self.root.path().join("ghidra-cache"),
            ),
            ("application.tempdir", temporary.clone()),
            ("java.io.tmpdir", temporary.clone()),
        ] {
            java_options.push_str(&format!(" \"-D{property}={}\"", path.display()));
        }
        command
            .current_dir(self.root.path())
            .env("XDG_CONFIG_HOME", self.root.path().join("config"))
            .env("XDG_CACHE_HOME", self.root.path().join("cache"))
            .env("TMPDIR", &temporary)
            .env("TMP", &temporary)
            .env("TEMP", &temporary)
            .env("JAVA_TOOL_OPTIONS", java_options)
            .env_remove("GHIDRA_INSTALL_DIR")
            .env("GHIDRA_JAR", &self.jar)
            .env("GHIDRA_CLI_CONFIG", self.root.path().join("config.yaml"))
            .env("GHIDRA_PROJECT_DIR", self.root.path().join("projects"))
            .arg("--json")
            .arg("--project")
            .arg(project)
            .args(args);
        let output =
            common::run_command_with_output(&mut command, Duration::from_secs(300)).unwrap();
        assert!(output.status.success(), "{args:?}: {output:?}");
        json_output::from_slice(&output.stdout).unwrap()
    }

    fn client(&self, project: &Path) -> BridgeClient {
        BridgeClient::new(bridge::is_bridge_running(project).expect("JAR bridge running"))
    }
}

impl Drop for JarRuntime {
    fn drop(&mut self) {
        for project in [&self.project, &self.restored] {
            bridge::stop_bridge(project).expect("stop standalone JAR bridge before cleanup");
        }
    }
}

#[test]
fn official_jar_runs_detached_with_native_tools_and_durable_project_operations() {
    require_ghidra!();
    let runtime = JarRuntime::new();
    let project = &runtime.project;
    let doctor = runtime.run(project, &["doctor", "--runtime"]);
    assert_eq!(doctor["installation"]["kind"], "jar", "{doctor}");
    assert_eq!(
        doctor["installation"]["path"],
        serde_json::json!(runtime.jar)
    );
    assert_eq!(doctor["runtime"]["status"], "success", "{doctor}");

    let binary = common::fixture::fixture_binary();
    // Ghidra rejects Japanese program names; project directories support Unicode.
    let program = "sample program";
    runtime.run(
        project,
        &[
            "program",
            "import",
            binary.to_str().unwrap(),
            "--name",
            program,
        ],
    );
    runtime.run(project, &["bridge", "start", "--program", program]);
    let client = runtime.client(project);
    let function = common::helpers::get_fixture_function(&client, "add_numbers");
    let decompiled = client
        .decompile(function.address.clone(), false, false, false, false)
        .unwrap();
    assert!(
        !decompiled["code"].as_str().unwrap().is_empty(),
        "{decompiled}"
    );
    let found = client
        .find_bytes_regex_with_limit("super_secret_key_[0-9]+", None)
        .unwrap();
    assert!(found["count"].as_u64().unwrap() > 0, "{found}");

    let script = runtime.root.path().join("PersistJarComment.java");
    std::fs::write(
        &script,
        r#"import ghidra.app.script.GhidraScript;
public class PersistJarComment extends GhidraScript {
    public void run() throws Exception {
        setEOLComment(toAddr(getScriptArgs()[0]), "standalone JAR persisted comment");
    }
}
"#,
    )
    .unwrap();
    runtime.run(
        project,
        &[
            "script",
            "run",
            script.to_str().unwrap(),
            "--",
            &function.address,
        ],
    );
    runtime.run(project, &["bridge", "stop"]);
    let reopened = runtime.run(
        project,
        &["comment", "get", &function.address, "--program", program],
    );
    assert!(reopened
        .to_string()
        .contains("standalone JAR persisted comment"));

    // Archive closes the live bridge, then uses the one-shot maintenance launcher.
    let archive = runtime.root.path().join("saved project's.gar");
    runtime.run(
        project,
        &[
            "project",
            "archive",
            project.to_str().unwrap(),
            "--output",
            archive.to_str().unwrap(),
        ],
    );
    assert!(bridge::is_bridge_running(project).is_none());
    runtime.run(
        project,
        &[
            "project",
            "restore",
            archive.to_str().unwrap(),
            runtime.restored.to_str().unwrap(),
        ],
    );
    let restored = runtime.run(
        &runtime.restored,
        &["comment", "get", &function.address, "--program", program],
    );
    assert!(restored
        .to_string()
        .contains("standalone JAR persisted comment"));
    runtime.run(&runtime.restored, &["bridge", "stop"]);
    runtime.run(
        project,
        &["project", "delete", runtime.restored.to_str().unwrap()],
    );
    assert!(!runtime.restored.with_extension("gpr").exists());
    assert!(!runtime.restored.with_extension("rep").exists());
}
