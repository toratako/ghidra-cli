use super::BridgeClient;
use anyhow::Result;
use serde_json::json;

impl BridgeClient {
    /// List strings.
    pub fn list_strings(
        &self,
        limit: Option<usize>,
        filter: Option<String>,
        offset: Option<usize>,
    ) -> Result<serde_json::Value> {
        self.send_command(
            "list_strings",
            Some(json!({"limit": limit, "filter": filter, "offset": offset})),
        )
    }

    /// Get cross-references to all defined strings matching a pattern.
    pub fn string_refs(&self, pattern: String) -> Result<serde_json::Value> {
        self.send_command("string_refs", Some(json!({"pattern": pattern})))
    }

    #[allow(dead_code)] // Public library API; CLI uses the planned fetch limit.
    pub fn find_string(&self, pattern: &str) -> Result<serde_json::Value> {
        self.find_string_with_limit(pattern, None)
    }

    pub fn find_string_with_limit(
        &self,
        pattern: &str,
        limit: Option<usize>,
    ) -> Result<serde_json::Value> {
        self.find_string_page(pattern, limit, None, None)
    }

    /// Find defined strings, applying both contains predicates before offset/limit.
    pub fn find_string_page(
        &self,
        pattern: &str,
        limit: Option<usize>,
        filter: Option<String>,
        offset: Option<usize>,
    ) -> Result<serde_json::Value> {
        self.send_command(
            "find_string",
            Some(json!({"pattern": pattern, "limit": limit, "filter": filter, "offset": offset})),
        )
    }

    #[allow(dead_code)] // Public library API; CLI uses the planned fetch limit.
    pub fn find_text(&self, text: &str, encoding: &str) -> Result<serde_json::Value> {
        self.find_text_with_limit(text, encoding, None)
    }

    pub fn find_text_with_limit(
        &self,
        text: &str,
        encoding: &str,
        limit: Option<usize>,
    ) -> Result<serde_json::Value> {
        self.send_command(
            "find_text",
            Some(json!({"text": text, "encoding": encoding, "limit": limit})),
        )
    }

    #[allow(dead_code)] // Public library API; CLI uses the planned fetch limit.
    pub fn find_bytes(&self, hex: &str) -> Result<serde_json::Value> {
        self.find_bytes_with_limit(hex, None)
    }

    pub fn find_bytes_with_limit(
        &self,
        hex: &str,
        limit: Option<usize>,
    ) -> Result<serde_json::Value> {
        self.send_command("find_bytes", Some(json!({"hex": hex, "limit": limit})))
    }

    /// Search program memory using Ghidra's native byte regular expressions.
    pub fn find_bytes_regex_with_limit(
        &self,
        pattern: &str,
        limit: Option<usize>,
    ) -> Result<serde_json::Value> {
        self.send_command(
            "find_bytes_regex",
            Some(json!({"pattern": pattern, "limit": limit})),
        )
    }

    pub fn find_instruction(
        &self,
        pattern: &str,
        start: Option<&str>,
        end: Option<&str>,
        case_sensitive: bool,
        limit: Option<usize>,
    ) -> Result<serde_json::Value> {
        self.send_command(
            "find_instruction",
            Some(json!({
                "pattern": pattern, "start": start, "end": end,
                "case_sensitive": case_sensitive, "limit": limit,
            })),
        )
    }
}
