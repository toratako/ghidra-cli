//! Import checkpoints and failure recovery after durable side effects.

use serde_json::json;
use std::path::Path;

pub(super) struct ImportProgress {
    pub(super) stage: &'static str,
    pub(super) imported: &'static str,
    pub(super) analysis: &'static str,
    pub(super) program: Option<String>,
    pub(super) receipt: Option<serde_json::Value>,
}

impl ImportProgress {
    pub(super) fn new(no_analyze: bool) -> Self {
        Self {
            stage: "import.validate",
            imported: "not_started",
            analysis: if no_analyze { "skipped" } else { "not_started" },
            program: None,
            receipt: None,
        }
    }

    pub(super) fn failure(&self, error: anyhow::Error, project: &Path) -> anyhow::Error {
        let mut detail = crate::error::diagnostic_detail(&error);
        let fields = detail.as_object_mut().unwrap();
        fields.entry("stage").or_insert(json!(self.stage));
        fields.insert("workflow_stage".into(), json!(self.stage));
        fields
            .entry("import_status")
            .or_insert(json!(self.imported));
        fields
            .entry("analysis_status")
            .or_insert(json!(self.analysis));
        fields.insert("project".into(), json!(project));
        if let Some(diagnostics) = self
            .receipt
            .as_ref()
            .and_then(|receipt| receipt.get("loader_diagnostics"))
        {
            fields
                .entry("loader_diagnostics")
                .or_insert(diagnostics.clone());
        }
        if let Some(program) = &self.program {
            // Selecting the imported program can fail while saving the previous
            // selection. Recovery must retain that actual save target.
            fields.entry("program").or_insert(json!(program));
        }
        let mut message = format!(
            "{} failed: {error:#}. Import: {}; analysis: {}",
            self.stage,
            detail["import_status"].as_str().unwrap_or("unknown"),
            detail["analysis_status"].as_str().unwrap_or("unknown")
        );
        if detail["import_status"] == "saved" {
            if detail["transaction_failed"] == true {
                message.push_str(
                    ". Do not re-import. Keep the bridge running: rollback is unconfirmed. \
                     Close outstanding transactions through their owner and inspect the program \
                     state before saving or retrying.",
                );
            } else if let Some(program) = detail["program"].as_str() {
                let command = if detail["outcome_unknown"] == true {
                    vec![
                        "ghidra-cli".to_owned(),
                        "job".into(),
                        "list".into(),
                        "--project".into(),
                        project.to_string_lossy().into_owned(),
                    ]
                } else if detail["save_failed"] == true {
                    vec![
                        "ghidra-cli".into(),
                        "program".into(),
                        "save".into(),
                        "--project".into(),
                        project.to_string_lossy().into_owned(),
                        "--program".into(),
                        program.into(),
                    ]
                } else {
                    let mut command = vec!["ghidra-cli".to_owned()];
                    if detail["analysis_status"] == "completed"
                        || detail["analysis_status"] == "skipped"
                    {
                        command.extend(["bridge".into(), "start".into()]);
                    } else {
                        command.extend(["analysis".into(), "run".into()]);
                    }
                    command.extend([
                        "--project".into(),
                        project.to_string_lossy().into_owned(),
                        "--program".into(),
                        program.into(),
                    ]);
                    command
                };
                message.push_str(&format!(
                    ". Do not re-import. After resolving the cause, recovery arguments: {}",
                    json!(command)
                ));
                detail["recovery"] = json!(command);
            }
        }
        error.context(crate::ipc::protocol::BridgeCommandError { message, detail })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::protocol::{BridgeCommandError, BridgeTimeoutError};

    #[test]
    fn saved_checkpoint_keeps_underlying_path_and_recovery_selection() {
        let project = Path::new("projects/with spaces");
        let path = Path::new("data/bridge state");
        let progress = ImportProgress {
            stage: "bridge.start",
            imported: "saved",
            analysis: "completed",
            program: Some("saved-name".into()),
            receipt: Some(json!({"loader_diagnostics": {"text": "loader evidence"}})),
        };
        let error = progress.failure(
            crate::error::path_io(
                "bridge.state_directory",
                path,
                std::io::Error::from(std::io::ErrorKind::PermissionDenied),
            )
            .into(),
            project,
        );
        let detail = crate::error::diagnostic_detail(&error);
        assert_eq!(detail["stage"], "bridge.state_directory");
        assert_eq!(detail["workflow_stage"], "bridge.start");
        assert_eq!(detail["path"], json!(path));
        assert_eq!(detail["import_status"], "saved");
        assert_eq!(detail["loader_diagnostics"]["text"], "loader evidence");
        assert_eq!(
            detail["recovery"],
            json!([
                "ghidra-cli",
                "bridge",
                "start",
                "--project",
                project,
                "--program",
                "saved-name"
            ])
        );
        assert!(error.to_string().contains("Do not re-import"));
    }

    #[test]
    fn analysis_timeout_or_save_failure_never_recommends_replaying_analysis() {
        let progress = ImportProgress {
            stage: "import.analysis",
            imported: "saved",
            analysis: "unknown",
            program: Some("saved-name".into()),
            receipt: Some(json!({"loader_diagnostics": {"text": "loader evidence"}})),
        };
        let timeout = progress.failure(
            BridgeTimeoutError {
                command: "analysis_run".into(),
                timeout_secs: 1,
            }
            .into(),
            Path::new("project"),
        );
        assert!(timeout.downcast_ref::<BridgeTimeoutError>().is_some());
        assert_eq!(
            crate::error::diagnostic_detail(&timeout)["loader_diagnostics"]["text"],
            "loader evidence"
        );
        assert_eq!(
            crate::error::diagnostic_detail(&timeout)["recovery"],
            json!(["ghidra-cli", "job", "list", "--project", "project"])
        );
        let save = progress.failure(
            BridgeCommandError {
                message: "Save failed".into(),
                detail: json!({"save_failed": true}),
            }
            .into(),
            Path::new("project"),
        );
        assert_eq!(
            crate::error::diagnostic_detail(&save)["recovery"][1],
            "program"
        );
        assert_eq!(
            crate::error::diagnostic_detail(&save)["recovery"][2],
            "save"
        );
    }

    #[test]
    fn lost_analysis_response_never_recommends_replaying_analysis() {
        let progress = ImportProgress {
            stage: "import.analysis",
            imported: "saved",
            analysis: "unknown",
            program: Some("saved-name".into()),
            receipt: None,
        };
        let error = progress.failure(
            crate::ipc::protocol::BridgeOutcomeUnknownError {
                command: "analysis_run".into(),
            }
            .into(),
            Path::new("project"),
        );
        let detail = crate::error::diagnostic_detail(&error);
        assert_eq!(detail["import_status"], "saved");
        assert_eq!(detail["analysis_status"], "unknown");
        assert_eq!(detail["outcome_unknown"], true);
        assert_eq!(
            detail["recovery"],
            json!(["ghidra-cli", "job", "list", "--project", "project"])
        );
        assert!(!error.to_string().contains("\"analysis\",\"run\""));
    }

    #[test]
    fn unconfirmed_analysis_rollback_keeps_the_bridge_running_without_a_retry_command() {
        let progress = ImportProgress {
            stage: "import.analysis",
            imported: "saved",
            analysis: "unknown",
            program: Some("saved-name".into()),
            receipt: None,
        };
        let error = progress.failure(
            BridgeCommandError {
                message: "Rollback failed".into(),
                detail: json!({"transaction_failed": true}),
            }
            .into(),
            Path::new("project"),
        );
        let detail = crate::error::diagnostic_detail(&error);
        assert_eq!(detail["import_status"], "saved");
        assert_eq!(detail["transaction_failed"], true);
        assert!(detail.get("recovery").is_none());
        let message = error.to_string();
        assert!(message.contains("Do not re-import"), "{message}");
        assert!(message.contains("Keep the bridge running"), "{message}");
    }

    #[test]
    fn import_selection_save_failure_recovers_the_previous_program() {
        let progress = ImportProgress {
            stage: "import.analysis",
            imported: "saved",
            analysis: "unknown",
            program: Some("new-import".into()),
            receipt: Some(json!({"loader_diagnostics": {"text": "loader evidence"}})),
        };
        let error = progress.failure(
            crate::ipc::protocol::BridgeCommandError {
                message: "Save failed while switching programs".into(),
                detail: json!({"save_failed": true, "saved": false, "program": "/previous"}),
            }
            .into(),
            Path::new("project"),
        );
        let detail = crate::error::diagnostic_detail(&error);
        assert_eq!(detail["program"], "/previous");
        assert_eq!(detail["loader_diagnostics"]["text"], "loader evidence");
        assert_eq!(
            detail["recovery"],
            json!([
                "ghidra-cli",
                "program",
                "save",
                "--project",
                "project",
                "--program",
                "/previous"
            ])
        );
    }

    #[test]
    fn loader_diagnostics_survive_later_workflow_failures() {
        let diagnostics = json!({
            "text": "loader evidence\n", "truncated": false,
            "retained_characters": 16, "original_characters": 16,
            "maximum_characters": 16384
        });
        for stage in [
            "bridge.start",
            "program.open",
            "program.info",
            "import.analysis",
        ] {
            let progress = ImportProgress {
                stage,
                imported: "saved",
                analysis: "skipped",
                program: Some("saved-name".into()),
                receipt: Some(json!({"loader_diagnostics": diagnostics})),
            };
            let error = progress.failure(
                BridgeCommandError {
                    message: "later stage failed".into(),
                    detail: json!({"stage": "native.failure", "evidence": "keep"}),
                }
                .into(),
                Path::new("project"),
            );
            let detail = crate::error::diagnostic_detail(&error);
            assert_eq!(detail["loader_diagnostics"], diagnostics);
            assert_eq!(detail["stage"], "native.failure");
            assert_eq!(detail["workflow_stage"], stage);
            assert_eq!(detail["evidence"], "keep");
            assert_eq!(detail["import_status"], "saved");
            assert_eq!(detail["analysis_status"], "skipped");
        }
    }
}
