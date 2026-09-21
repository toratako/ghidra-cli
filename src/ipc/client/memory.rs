use super::BridgeClient;
use anyhow::Result;
use serde_json::json;

impl BridgeClient {
    /// Get memory map.
    pub fn memory_map(&self) -> Result<serde_json::Value> {
        self.send_command("memory_map", None)
    }

    /// Get instruction, data, function, and memory details at a target.
    pub fn memory_info(&self, address: &str) -> Result<serde_json::Value> {
        self.send_command("memory_info", Some(json!({"address": address})))
    }

    pub fn memory_write(&self, address: &str, hex: &str) -> Result<serde_json::Value> {
        self.send_command(
            "memory_write",
            Some(json!({"address": address, "hex": hex})),
        )
    }

    /// Read existing instructions belonging to a function, including disjoint body ranges.
    pub fn function_disasm(&self, target: &str, limit: Option<usize>) -> Result<serde_json::Value> {
        self.send_command(
            "function_disasm",
            Some(json!({"target": target, "limit": limit})),
        )
    }

    /// Read existing instructions from the resolved start, up to `limit` (0/None = unlimited).
    pub fn disasm(&self, address: &str, limit: Option<usize>) -> Result<serde_json::Value> {
        self.send_command("disasm", Some(json!({"address": address, "limit": limit})))
    }

    /// Read existing instructions in an inclusive range. A distinct wire name
    /// prevents older bridges from silently ignoring the end address.
    pub fn disasm_range(
        &self,
        start: &str,
        end: &str,
        limit: Option<usize>,
    ) -> Result<serde_json::Value> {
        self.send_command(
            "disasm_range",
            Some(json!({"start": start, "end": end, "limit": limit})),
        )
    }

    /// Define instructions from `target`, optionally bounded by inclusive `end`.
    /// Returns a change receipt only; use `disasm` to read instruction rows.
    pub fn define_code(&self, target: &str, end: Option<&str>) -> Result<serde_json::Value> {
        self.send_command("define_code", Some(json!({"target": target, "end": end})))
    }

    /// Clear all code units overlapping `[start, end]`, optionally
    /// re-disassembling at `disasm_at` in the same call.
    pub fn clear_range(
        &self,
        start: &str,
        end: &str,
        disasm_at: Option<&str>,
    ) -> Result<serde_json::Value> {
        self.send_command(
            "clear_range",
            Some(json!({"start": start, "end": end, "disasm_at": disasm_at})),
        )
    }
}
