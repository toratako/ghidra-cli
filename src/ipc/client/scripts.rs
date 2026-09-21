use super::BridgeClient;
use anyhow::Result;
use serde_json::json;

impl BridgeClient {
    pub fn script_run(
        &self,
        script_path: &str,
        args: &[String],
        expect: &[serde_json::Value],
        allow_empty: bool,
    ) -> Result<serde_json::Value> {
        let payload = json!({"path": script_path, "args": args});
        self.script_run_payload(payload, expect, allow_empty)
    }

    /// Run a script whose Java source was read client-side (e.g. from stdin)
    /// instead of loaded from a path on disk. The bridge compiles it the same
    /// way as `script_run`, just staged from a temp file server-side.
    pub fn script_run_source(
        &self,
        source: &str,
        args: &[String],
        expect: &[serde_json::Value],
        allow_empty: bool,
    ) -> Result<serde_json::Value> {
        let payload = json!({"source": source, "args": args});
        self.script_run_payload(payload, expect, allow_empty)
    }

    fn script_run_payload(
        &self,
        mut payload: serde_json::Value,
        expect: &[serde_json::Value],
        allow_empty: bool,
    ) -> Result<serde_json::Value> {
        if !expect.is_empty() {
            payload["expect"] = serde_json::Value::Array(expect.to_vec());
            payload["allow_empty"] = json!(allow_empty);
        }
        self.send_command("script_run", Some(payload))
    }

    pub fn script_list(&self) -> Result<serde_json::Value> {
        self.send_command("script_list", None)
    }
}
