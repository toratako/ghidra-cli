//! IPC protocol types for bridge communication.
//!
//! Defines the request/response format for CLI ↔ Java bridge communication.
//! Uses simple JSON: {"command":"...", "args":{...}} → {"status":"...", "data":{...}}

use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u64 = 4;

/// Request to the Java bridge.
#[derive(Debug, Serialize)]
pub struct BridgeRequest {
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<serde_json::Value>,
}

/// Response from the Java bridge.
#[derive(Debug, Deserialize)]
pub struct BridgeResponse<T = serde_json::Value> {
    pub status: String,
    #[serde(default)]
    pub job_id: Option<String>,
    /// Missing on controls/admission failures; explicit null means no program selected.
    #[serde(default, deserialize_with = "deserialize_selected_program")]
    pub selected_program: Option<Option<String>>,
    pub data: Option<T>,
    #[serde(default)]
    pub message: Option<String>,
    /// Structured detail attached to an error response (e.g. the containing
    /// function's name/entry/size on a "function already exists" error, or the
    /// conflicting data unit's type/range on a "listing define-data" conflict). Absent
    /// on success responses and on errors that carry only a message.
    #[serde(default)]
    pub detail: Option<serde_json::Value>,
}

fn deserialize_selected_program<'de, D>(deserializer: D) -> Result<Option<Option<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer).map(Some)
}

/// An error surfaced by the bridge that carries structured detail alongside its
/// message (e.g. the containing function's name/entry/size for a "function
/// already exists" error). `Display` prints just the message, matching plain
/// bridge errors, so existing `anyhow`-based error handling is unaffected;
/// callers that want the structured detail can `downcast_ref` for it.
#[derive(Debug)]
pub struct BridgeCommandError {
    pub message: String,
    pub detail: serde_json::Value,
}

impl std::fmt::Display for BridgeCommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for BridgeCommandError {}

/// Identity of a sent program request whose final response was not received.
/// Kept out of normal results and confirmed command errors.
#[derive(Debug)]
pub struct BridgeJob {
    pub id: String,
    pub command: String,
}

impl std::fmt::Display for BridgeJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Job {} ({})", self.id, self.command)
    }
}

impl std::error::Error for BridgeJob {}

/// The client gave up waiting for a response within the configured read
/// timeout, distinct from the bridge actually reporting a failure: the
/// program job this request queued may still be running server-side and can
/// go on to complete normally after the client has already exited (see
/// `ghidra-cli job list`). Kept as a distinct error type (rather than a plain
/// `anyhow::bail!`) so callers -- `main`'s exit-code selection, or a wrapper
/// script via `downcast_ref` -- can tell "I gave up waiting" apart from "this
/// genuinely failed" without string-matching the message.
#[derive(Debug)]
pub struct BridgeTimeoutError {
    pub command: String,
    pub timeout_secs: u64,
}

impl std::fmt::Display for BridgeTimeoutError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Bridge did not respond within {}s while running '{}' — the operation's \
             outcome is unknown. Inspect the job result, raise the wait via \
             GHIDRA_CLI_READ_TIMEOUT (seconds; 0 = wait indefinitely), or use \
             GHIDRA_CLI_OP_TIMEOUT for long analyze/import operations.",
            self.timeout_secs, self.command
        )
    }
}

impl std::error::Error for BridgeTimeoutError {}

/// A request was sent, but no trustworthy command response was received.
/// Retrying could replay an already committed edit.
#[derive(Debug)]
pub struct BridgeOutcomeUnknownError {
    pub command: String,
}

impl std::fmt::Display for BridgeOutcomeUnknownError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "The command outcome is unknown for '{}'; changes may already have been applied and saved. Inspect the result and program state before repeating it.", self.command)
    }
}

impl std::error::Error for BridgeOutcomeUnknownError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_serialization() {
        let request = BridgeRequest {
            command: "ping".to_string(),
            job_id: None,
            program: None,
            args: None,
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("ping"));
        assert!(!json.contains("args"));
    }

    #[test]
    fn test_request_with_args() {
        let request = BridgeRequest {
            command: "list_functions".to_string(),
            job_id: Some(uuid::Uuid::new_v4().to_string()),
            program: Some("/old/app".to_owned()),
            args: Some(serde_json::json!({"limit": 100})),
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("list_functions"));
        assert!(json.contains("100"));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&json).unwrap()["program"],
            "/old/app"
        );
    }

    #[test]
    fn test_response_deserialization() {
        let json = r#"{"status":"success","data":{"count":42}}"#;
        let response: BridgeResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.status, "success");
        assert!(response.data.is_some());
    }

    #[test]
    fn response_selection_distinguishes_unobserved_closed_and_selected() {
        for (wire, expected) in [
            (r#"{"status":"error"}"#, None),
            (
                r#"{"status":"success","selected_program":null}"#,
                Some(None),
            ),
            (
                r#"{"status":"error","selected_program":"/old/app"}"#,
                Some(Some("/old/app".to_owned())),
            ),
        ] {
            let response: BridgeResponse = serde_json::from_str(wire).unwrap();
            assert_eq!(response.selected_program, expected);
        }
    }

    #[test]
    fn test_error_response() {
        let json = r#"{"status":"error","message":"Something went wrong"}"#;
        let response: BridgeResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.status, "error");
        assert_eq!(response.message.as_ref().unwrap(), "Something went wrong");
    }
}
