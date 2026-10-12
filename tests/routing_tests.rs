//! CLI routing contracts, verified against recorded requests without Ghidra.

#[path = "support/json.rs"]
mod json_output;

use ghidra_cli::ghidra::bridge;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[path = "routing/analysis.rs"]
mod analysis;
#[path = "routing/batch.rs"]
mod batch;
#[path = "routing/batch_execution.rs"]
mod batch_execution;
#[path = "routing/batch_syntax.rs"]
mod batch_syntax;
#[path = "routing/commands.rs"]
mod commands;
#[path = "routing/function_candidates.rs"]
mod function_candidates;
#[path = "routing/functions.rs"]
mod functions;
#[path = "routing/imports.rs"]
mod imports;
#[path = "support/installation.rs"]
mod installation_fixture;
#[path = "routing/listing.rs"]
mod listing;
#[path = "routing/management.rs"]
mod management;
#[path = "routing/memory.rs"]
mod memory;
#[path = "routing/namespaces.rs"]
mod namespaces;
#[path = "routing/output.rs"]
mod output;
#[path = "routing/program.rs"]
mod program;
#[path = "routing/program_analysis.rs"]
mod program_analysis;
#[path = "routing/queries.rs"]
mod queries;
#[path = "routing/recorded.rs"]
mod recorded;
#[path = "routing/references.rs"]
mod references;
#[path = "routing/responses.rs"]
mod responses;
#[path = "routing/rollout.rs"]
mod rollout;
#[path = "routing/scripts.rs"]
mod scripts;
#[path = "routing/search.rs"]
mod search;
#[path = "routing/symbols.rs"]
mod symbols;
#[path = "routing/tables.rs"]
mod tables;
#[path = "routing/thunks.rs"]
mod thunks;
#[path = "routing/types.rs"]
mod types;
#[path = "routing/virtual_callers.rs"]
mod virtual_callers;

use responses::{api_list_fixture, call_graph_fixture, call_rows_fixture, symbol_fixture};

fn batch_path_argument(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
}

fn batch_arguments(args: &[&str]) -> String {
    args.iter()
        .map(|arg| format!("'{}'", arg.replace('\'', "'\\''")))
        .collect::<Vec<_>>()
        .join(" ")
}

const JOB_ID: &str = "2c7a3b91-f960-4b85-87d7-e90cf7bf0625";
const ACTIVE_JOB_ID: &str = "73d7a267-ed73-4548-b8ee-24c7af918720";

struct RecordedBridge {
    root: tempfile::TempDir,
    project: PathBuf,
    port: u16,
    requests: Arc<Mutex<Vec<Value>>>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl RecordedBridge {
    fn new() -> Self {
        Self::with_info(
            json!({"protocol_version": 4, "auto_save": true, "atomic_edits": true, "named_import": true, "explicit_addresses": true}),
        )
    }

    fn with_info(bridge_info: Value) -> Self {
        // Match the physical working directory seen by subprocesses on macOS,
        // where the temporary directory can be reached through /var or /private/var.
        let root = tempfile::Builder::new()
            .prefix("routing tests' ")
            .tempdir_in(dunce::canonicalize(std::env::temp_dir()).unwrap())
            .unwrap();
        installation_fixture::write(&root.path().join("unused-install"));
        // Match CLI normalization before hashing the discovery path on Windows.
        let project = std::path::absolute(root.path().join("projects/project")).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::fs::write(bridge::port_file_path(&project).unwrap(), port.to_string()).unwrap();
        std::fs::write(
            bridge::pid_file_path(&project).unwrap(),
            std::process::id().to_string(),
        )
        .unwrap();
        std::fs::write(root.path().join("config.yaml"), "default_limit: 1\n").unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        let worker = std::thread::spawn(move || {
            let mut session = recorded::Session::new(bridge_info);
            for connection in listener.incoming() {
                let mut connection = connection.unwrap();
                connection
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let mut line = String::new();
                BufReader::new(&connection).read_line(&mut line).unwrap();
                if line.is_empty() {
                    continue;
                }
                let request: Value = serde_json::from_str(&line).unwrap();
                if request["command"] == "test_stop" {
                    break;
                }
                captured.lock().unwrap().push(request.clone());
                match session.reply(&request) {
                    recorded::Reply::Send(response) => {
                        writeln!(connection, "{response}").unwrap();
                        session.after_send(&request, &response);
                    }
                    recorded::Reply::Timeout => {
                        std::thread::sleep(std::time::Duration::from_secs(2));
                    }
                    recorded::Reply::Disconnect => {}
                }
            }
        });
        Self {
            root,
            project,
            port,
            requests,
            worker: Some(worker),
        }
    }

    fn command(&self) -> assert_cmd::Command {
        let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli");
        cmd.current_dir(self.root.path())
            .env("GHIDRA_CLI_CONFIG", self.root.path().join("config.yaml"))
            .env_remove("GHIDRA_CLI_DECOMPILE_TIMEOUT")
            .env_remove("GHIDRA_JAR")
            .env(
                "GHIDRA_INSTALL_DIR",
                self.root.path().join("unused-install"),
            )
            .arg("--project")
            .arg(&self.project)
            .timeout(std::time::Duration::from_secs(15));
        cmd
    }

    fn run(&self, args: &[&str]) -> Value {
        let output = self.command().args(args).output().unwrap();
        assert!(output.status.success(), "{args:?}: {output:?}");
        crate::json_output::from_slice(&output.stdout).unwrap()
    }
}

impl Drop for RecordedBridge {
    fn drop(&mut self) {
        if let Ok(mut connection) = TcpStream::connect(("127.0.0.1", self.port)) {
            let _ = writeln!(connection, "{{\"command\":\"test_stop\"}}");
        }
        let _ = self.worker.take().unwrap().join();
        let _ = std::fs::remove_file(bridge::port_file_path(&self.project).unwrap());
        let _ = std::fs::remove_file(bridge::pid_file_path(&self.project).unwrap());
    }
}
