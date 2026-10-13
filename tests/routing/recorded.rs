//! Program selection, wire envelopes, and injected failures for the recorded bridge.

use serde_json::{json, Value};

pub(super) enum Reply {
    Send(Value),
    Timeout,
    Disconnect,
}

pub(super) struct Session {
    bridge_info: Value,
    program: String,
    has_current_program: bool,
}

impl Session {
    pub(super) fn new(bridge_info: Value) -> Self {
        Self {
            bridge_info,
            program: String::from("A"),
            has_current_program: true,
        }
    }

    pub(super) fn reply(&mut self, request: &Value) -> Reply {
        let args = &request["args"];
        if request["command"] == "program_save"
            && self.bridge_info["test_program_save_lost_response"] == true
        {
            return Reply::Disconnect;
        }
        if request["command"] == "job_result" {
            if let Some(response) = self.bridge_info.get("test_job_result_response") {
                return Reply::Send(response.clone());
            }
        }
        if let Some(target) = request["program"].as_str() {
            if target == "missing-program" {
                return Reply::Send(
                    json!({"status": "error", "job_id": request["job_id"], "selected_program": self.has_current_program.then_some(&self.program), "message": "Program not found: missing-program"}),
                );
            }
            self.program = target.to_owned();
            self.has_current_program = true;
        }
        let import_failure = &self.bridge_info["test_import_followup_error"];
        if matches!(
            request["command"].as_str(),
            Some("analysis_run" | "open_program")
        ) && import_failure["command"] == request["command"]
        {
            if import_failure["disconnect"] == true {
                return Reply::Disconnect;
            }
            let selected_program = import_failure
                .get("selected_program")
                .cloned()
                .unwrap_or_else(|| json!(self.has_current_program.then_some(&self.program)));
            return Reply::Send(json!({
                "status": "error", "job_id": request["job_id"],
                "selected_program": selected_program, "message": "Import follow-up failed",
                "detail": import_failure["detail"],
            }));
        }
        if args["text"] == "test-save-failure"
            || (request["command"] == "program_save"
                && self.bridge_info["test_save_failure"] == true)
        {
            return Reply::Send(
                json!({"status": "error", "job_id": request["job_id"], "selected_program": self.has_current_program.then_some(&self.program), "message": "Save failed", "detail": {"save_failed": true}}),
            );
        }
        if args["text"] == "test-timeout" {
            return Reply::Timeout;
        }
        if args["text"] == "test-lost-response" {
            return Reply::Disconnect;
        }
        if args["text"] == "test-unidentified-error" {
            return Reply::Send(json!({
                "status": "error", "selected_program": "C", "message": "Edit failed"
            }));
        }
        if args["text"] == "test-malformed-detail" {
            return Reply::Send(json!({
                "status": "error", "job_id": request["job_id"],
                "selected_program": self.program, "message": "Edit failed", "detail": []
            }));
        }
        if args["text"] == "test-unobserved-success" {
            return Reply::Send(json!({
                "status": "success", "job_id": request["job_id"], "data": {"changed": true}
            }));
        }
        if args["text"] == "test-rollback" {
            return Reply::Send(
                json!({"status": "error", "job_id": request["job_id"], "selected_program": self.has_current_program.then_some(&self.program), "message": "Edit rejected", "detail": {"rolled_back": true, "program": self.program}}),
            );
        }
        let data = match request["command"].as_str().unwrap() {
            "open_program" => {
                self.program = args["program"].as_str().unwrap().to_owned();
                self.has_current_program = true;
                json!({"program": self.program})
            }
            "program_close" => {
                self.has_current_program = false;
                json!({"closed": true})
            }
            "program_delete" => {
                if args["program"] == self.program {
                    self.has_current_program = false;
                }
                json!({"deleted": true})
            }
            "list_programs" => json!({
                "programs": [{"name": "A"}, {"name": "B"}],
                "has_current_program": self.has_current_program,
                "current_program_name": self.has_current_program.then_some(&self.program),
            }),
            _ => super::responses::data(request, &self.program, &self.bridge_info),
        };
        let mut response = json!({"status": "success", "job_id": request["job_id"], "data": data});
        if request.get("job_id").is_some() {
            response["selected_program"] = json!(self.has_current_program.then_some(&self.program));
        }
        Reply::Send(response)
    }

    // Simulate another client only after a successful job response was sent.
    pub(super) fn after_send(&mut self, request: &Value, response: &Value) {
        if response["status"] == "success" && request.get("job_id").is_some() {
            if let Some(interleaved) = self.bridge_info["test_interleave_program"].as_str() {
                self.program = interleaved.to_owned();
                self.has_current_program = true;
            }
        }
    }
}
