use super::transport::long_op_timeout;
use super::BridgeClient;
use anyhow::Result;
use serde_json::json;

impl BridgeClient {
    /// Get program info.
    pub fn program_info(&self) -> Result<serde_json::Value> {
        self.send_command("program_info", None)
    }

    /// List all program relocations.
    pub fn program_list_relocations(&self) -> Result<serde_json::Value> {
        self.send_command("program_list_relocations", None)
    }

    /// Import a binary. Unbounded read timeout: importing a large binary can
    /// take a long time.
    pub fn import_binary(
        &self,
        binary_path: &str,
        program: Option<&str>,
    ) -> Result<serde_json::Value> {
        self.send_command_with_timeout(
            "import",
            Some(json!({"binary_path": binary_path, "program": program})),
            long_op_timeout(),
        )
    }

    /// Analyze the current program with full, bounded seed, or pending work.
    /// Analysis can exceed any fixed cap on large/complex binaries.
    pub fn analysis_run(
        &self,
        start: Option<&str>,
        end: Option<&str>,
        pending: bool,
    ) -> Result<serde_json::Value> {
        anyhow::ensure!(
            start.is_some() == end.is_some(),
            "Analysis range requires both start and end"
        );
        anyhow::ensure!(
            !pending || start.is_none(),
            "Pending analysis cannot specify a range"
        );
        let mut args = serde_json::Map::new();
        if let (Some(start), Some(end)) = (start, end) {
            args.insert("start".into(), json!(start));
            args.insert("end".into(), json!(end));
        }
        if pending {
            args.insert("pending".into(), json!(true));
        }
        self.send_command_with_timeout("analysis_run", Some(args.into()), long_op_timeout())
    }

    pub fn analysis_option_list(&self) -> Result<serde_json::Value> {
        self.send_command("analysis_option_list", None)
    }

    pub fn analysis_option_get(&self, name: &str) -> Result<serde_json::Value> {
        self.send_command("analysis_option_get", Some(json!({"name": name})))
    }

    pub fn analysis_option_set(&self, name: &str, value: &str) -> Result<serde_json::Value> {
        self.send_command(
            "analysis_option_set",
            Some(json!({"name": name, "value": value})),
        )
    }

    /// List programs in the project.
    pub fn list_programs(&self) -> Result<serde_json::Value> {
        self.send_command("list_programs", None)
    }

    /// Open/switch to a program.
    pub fn open_program(&self, program: &str) -> Result<serde_json::Value> {
        self.send_command("open_program", Some(json!({"program": program})))
    }

    pub fn stats(&self) -> Result<serde_json::Value> {
        self.send_command("stats", None)
    }

    pub fn program_close(&self) -> Result<serde_json::Value> {
        self.send_command("program_close", None)
    }

    /// Flush pending changes without restarting the bridge.
    pub fn program_save(&self) -> Result<serde_json::Value> {
        self.send_command_with_timeout("program_save", None, long_op_timeout())
    }

    pub fn program_delete(&self, program: &str) -> Result<serde_json::Value> {
        self.send_command("program_delete", Some(json!({"program": program})))
    }

    pub fn program_export(&self, format: &str, output: Option<&str>) -> Result<serde_json::Value> {
        self.send_command(
            "program_export",
            Some(json!({"format": format, "output": output})),
        )
    }
}
