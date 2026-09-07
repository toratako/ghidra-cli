//! Bridge client for direct communication with the Java bridge.
//!
//! Connects directly to the Java GhidraCliBridge via TCP.
//! No intermediate daemon process is needed.

use std::time::Duration;

use anyhow::Result;
use serde_json::json;

mod transport;
use transport::long_op_timeout;

/// Native decompiler execution budget sent to Ghidra. Ghidra defines zero as
/// unbounded; that is the default because large, valid functions routinely take
/// longer than its historical 30-second background-analysis default.
fn decompile_timeout_secs() -> u32 {
    std::env::var("GHIDRA_CLI_DECOMPILE_TIMEOUT")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(0)
}

/// Client for communicating with the Ghidra Java bridge.
pub struct BridgeClient {
    port: u16,
}

impl BridgeClient {
    /// Create a client for a known port.
    pub fn new(port: u16) -> Self {
        Self { port }
    }

    /// Get the port this client connects to.
    #[allow(dead_code)]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Check if bridge is responding.
    ///
    /// Uses a short read timeout so readiness polling stays snappy (a missing
    /// or unbound socket fails fast rather than blocking).
    pub fn ping(&self) -> Result<bool> {
        match self.send_command_with_timeout("ping", None, Some(Duration::from_secs(5))) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Shutdown the bridge.
    pub fn shutdown(&self) -> Result<()> {
        self.send_command("shutdown", None)?;
        Ok(())
    }

    /// Get bridge status.
    pub fn status(&self) -> Result<serde_json::Value> {
        self.send_command("status", None)
    }

    /// Get one job, or the full bridge job status when no ID is supplied.
    pub fn job_status(&self, job_id: Option<u64>) -> Result<serde_json::Value> {
        self.send_command("job_status", Some(json!({"job_id": job_id})))
    }

    /// Request cooperative cancellation of a job. With no ID, cancel the active job.
    pub fn cancel_job(&self, job_id: Option<u64>) -> Result<serde_json::Value> {
        self.send_command("job_cancel", Some(json!({"job_id": job_id})))
    }

    /// Get bridge info (current program, project name, program count, uptime).
    pub fn bridge_info(&self) -> Result<serde_json::Value> {
        self.send_command("bridge_info", None)
    }

    /// List functions. `tags` restricts to functions carrying ALL of the given
    /// tags (server-side filter); `untagged` restricts to functions with no tags.
    pub fn list_functions(
        &self,
        limit: Option<usize>,
        filter: Option<String>,
        tags: &[String],
        untagged: bool,
    ) -> Result<serde_json::Value> {
        self.send_command(
            "list_functions",
            Some(json!({
                "limit": limit,
                "filter": filter,
                "tags": tags,
                "untagged": untagged,
            })),
        )
    }

    /// Decompile a function.
    pub fn decompile(
        &self,
        address: String,
        with_vars: bool,
        with_params: bool,
    ) -> Result<serde_json::Value> {
        self.send_command_with_timeout(
            "decompile",
            Some(json!({
                "address": address,
                "with_vars": with_vars,
                "with_params": with_params,
                "timeout_secs": decompile_timeout_secs(),
            })),
            long_op_timeout(),
        )
    }

    /// List strings.
    pub fn list_strings(
        &self,
        limit: Option<usize>,
        filter: Option<String>,
    ) -> Result<serde_json::Value> {
        self.send_command(
            "list_strings",
            Some(json!({"limit": limit, "filter": filter})),
        )
    }

    /// List imports.
    pub fn list_imports(&self, limit: Option<usize>) -> Result<serde_json::Value> {
        self.send_command("list_imports", Some(json!({"limit": limit})))
    }

    /// List exports.
    pub fn list_exports(&self, limit: Option<usize>) -> Result<serde_json::Value> {
        self.send_command("list_exports", Some(json!({"limit": limit})))
    }

    /// Get memory map.
    pub fn memory_map(&self) -> Result<serde_json::Value> {
        self.send_command("memory_map", None)
    }

    /// Get program info.
    pub fn program_info(&self) -> Result<serde_json::Value> {
        self.send_command("program_info", None)
    }

    /// Get cross-references to an address.
    pub fn xrefs_to(&self, address: String) -> Result<serde_json::Value> {
        self.send_command("xrefs_to", Some(json!({"address": address})))
    }

    /// Get cross-references to all defined strings matching a pattern.
    pub fn string_refs(&self, pattern: String) -> Result<serde_json::Value> {
        self.send_command("string_refs", Some(json!({"string": pattern})))
    }

    /// Get cross-references from an address.
    pub fn xrefs_from(&self, address: String) -> Result<serde_json::Value> {
        self.send_command("xrefs_from", Some(json!({"address": address})))
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

    /// Analyze the current program. Unbounded read timeout: full auto-analysis
    /// can exceed any fixed cap on large/complex binaries.
    pub fn analyze(&self) -> Result<serde_json::Value> {
        self.send_command_with_timeout("analyze", None, long_op_timeout())
    }

    pub fn pcode_at(&self, address: &str) -> Result<serde_json::Value> {
        self.send_command("pcode_at", Some(json!({"address": address})))
    }

    pub fn pcode_function(&self, function: &str, high: bool) -> Result<serde_json::Value> {
        self.send_command(
            "pcode_function",
            Some(json!({"function": function, "high": high})),
        )
    }

    pub fn analyzer_list(&self) -> Result<serde_json::Value> {
        self.send_command("analyzer_list", None)
    }

    pub fn analyzer_set(&self, name: &str, enabled: bool) -> Result<serde_json::Value> {
        self.send_command(
            "analyzer_set",
            Some(json!({"name": name, "enabled": enabled})),
        )
    }

    pub fn analyze_run(&self) -> Result<serde_json::Value> {
        self.send_command_with_timeout("analyze_run", None, long_op_timeout())
    }

    /// List programs in the project.
    pub fn list_programs(&self) -> Result<serde_json::Value> {
        self.send_command("list_programs", None)
    }

    /// Open/switch to a program.
    pub fn open_program(&self, program: &str) -> Result<serde_json::Value> {
        self.send_command("open_program", Some(json!({"program": program})))
    }

    // === Extended commands (symbols, types, comments, etc.) ===

    pub fn symbol_list(
        &self,
        limit: Option<usize>,
        filter: Option<&str>,
    ) -> Result<serde_json::Value> {
        self.send_command(
            "symbol_list",
            Some(json!({"limit": limit, "filter": filter})),
        )
    }

    pub fn symbol_get(&self, name: &str) -> Result<serde_json::Value> {
        self.send_command("symbol_get", Some(json!({"name": name})))
    }

    pub fn symbol_create(&self, address: &str, name: &str) -> Result<serde_json::Value> {
        self.send_command(
            "symbol_create",
            Some(json!({"address": address, "name": name})),
        )
    }

    /// `addresses` scopes the delete to exactly those symbols (by address);
    /// see `resolve_symbol_addresses` in app/execute.rs for how callers compute it.
    pub fn symbol_delete(&self, name: &str, addresses: &[String]) -> Result<serde_json::Value> {
        self.send_command(
            "symbol_delete",
            Some(json!({"name": name, "addresses": addresses})),
        )
    }

    /// `addresses` scopes the rename to exactly those symbols (by address);
    /// see `resolve_symbol_addresses` in app/execute.rs for how callers compute it.
    pub fn symbol_rename(
        &self,
        old_name: &str,
        new_name: &str,
        addresses: &[String],
    ) -> Result<serde_json::Value> {
        self.send_command(
            "symbol_rename",
            Some(json!({"old_name": old_name, "new_name": new_name, "addresses": addresses})),
        )
    }

    pub fn type_list(
        &self,
        limit: Option<usize>,
        filter: Option<&str>,
    ) -> Result<serde_json::Value> {
        self.send_command("type_list", Some(json!({"limit": limit, "filter": filter})))
    }

    /// List function tags (all tags, or one function's tags).
    pub fn tag_list(
        &self,
        limit: Option<usize>,
        function: Option<&str>,
    ) -> Result<serde_json::Value> {
        self.send_command(
            "tag_list",
            Some(json!({"limit": limit, "function": function})),
        )
    }

    /// Get the member functions of a tag.
    pub fn tag_get(&self, name: &str, limit: Option<usize>) -> Result<serde_json::Value> {
        self.send_command("tag_get", Some(json!({"name": name, "limit": limit})))
    }

    pub fn type_get(&self, name: &str) -> Result<serde_json::Value> {
        self.send_command("type_get", Some(json!({"name": name})))
    }

    pub fn type_create(&self, definition: &str) -> Result<serde_json::Value> {
        self.send_command("type_create", Some(json!({"definition": definition})))
    }

    pub fn type_import_c(&self, code: &str, category: Option<&str>) -> Result<serde_json::Value> {
        self.send_command(
            "type_import_c",
            Some(json!({"code": code, "category": category})),
        )
    }

    /// Apply a type at an address. With `force`, clears any conflicting data
    /// unit first instead of failing on it.
    pub fn type_apply_force(
        &self,
        address: &str,
        type_name: &str,
        force: bool,
    ) -> Result<serde_json::Value> {
        self.send_command(
            "type_apply",
            Some(json!({"address": address, "type_name": type_name, "force": force})),
        )
    }

    pub fn comment_list(
        &self,
        limit: Option<usize>,
        filter: Option<&str>,
    ) -> Result<serde_json::Value> {
        self.send_command(
            "comment_list",
            Some(json!({"limit": limit, "filter": filter})),
        )
    }

    pub fn comment_get(&self, address: &str) -> Result<serde_json::Value> {
        self.send_command("comment_get", Some(json!({"address": address})))
    }

    pub fn comment_set(
        &self,
        address: &str,
        text: &str,
        comment_type: Option<&str>,
    ) -> Result<serde_json::Value> {
        self.send_command(
            "comment_set",
            Some(json!({
                "address": address,
                "text": text,
                "comment_type": comment_type,
            })),
        )
    }

    pub fn comment_delete(&self, address: &str) -> Result<serde_json::Value> {
        self.send_command("comment_delete", Some(json!({"address": address})))
    }

    pub fn graph_calls(&self, limit: Option<usize>) -> Result<serde_json::Value> {
        self.send_command("graph_calls", Some(json!({"limit": limit})))
    }

    pub fn graph_callers(
        &self,
        function: &str,
        depth: Option<usize>,
        limit: Option<usize>,
    ) -> Result<serde_json::Value> {
        self.send_command(
            "graph_callers",
            Some(json!({"function": function, "depth": depth, "limit": limit})),
        )
    }

    pub fn graph_callees(
        &self,
        function: &str,
        depth: Option<usize>,
        limit: Option<usize>,
    ) -> Result<serde_json::Value> {
        self.send_command(
            "graph_callees",
            Some(json!({"function": function, "depth": depth, "limit": limit})),
        )
    }

    pub fn graph_export(&self, format: &str) -> Result<serde_json::Value> {
        self.send_command("graph_export", Some(json!({"format": format})))
    }

    pub fn find_string(&self, pattern: &str) -> Result<serde_json::Value> {
        self.send_command("find_string", Some(json!({"pattern": pattern})))
    }

    pub fn find_bytes(&self, hex: &str) -> Result<serde_json::Value> {
        self.send_command("find_bytes", Some(json!({"hex": hex})))
    }

    pub fn find_function(&self, pattern: &str) -> Result<serde_json::Value> {
        self.send_command("find_function", Some(json!({"pattern": pattern})))
    }

    pub fn find_calls(&self, function: &str) -> Result<serde_json::Value> {
        self.send_command("find_calls", Some(json!({"function": function})))
    }

    pub fn find_crypto(&self) -> Result<serde_json::Value> {
        self.send_command("find_crypto", None)
    }

    pub fn find_interesting(&self) -> Result<serde_json::Value> {
        self.send_command("find_interesting", None)
    }

    pub fn diff_programs(&self, program1: &str, program2: &str) -> Result<serde_json::Value> {
        self.send_command(
            "diff_programs",
            Some(json!({"program1": program1, "program2": program2})),
        )
    }

    pub fn diff_functions(&self, func1: &str, func2: &str) -> Result<serde_json::Value> {
        self.send_command(
            "diff_functions",
            Some(json!({"func1": func1, "func2": func2})),
        )
    }

    pub fn patch_bytes(&self, address: &str, hex: &str) -> Result<serde_json::Value> {
        self.send_command("patch_bytes", Some(json!({"address": address, "hex": hex})))
    }

    pub fn patch_nop(&self, address: &str, count: Option<usize>) -> Result<serde_json::Value> {
        self.send_command(
            "patch_nop",
            Some(json!({"address": address, "count": count})),
        )
    }

    pub fn patch_export(&self, output: &str) -> Result<serde_json::Value> {
        self.send_command("patch_export", Some(json!({"output": output})))
    }

    pub fn disasm(
        &self,
        address: &str,
        num_instructions: Option<usize>,
    ) -> Result<serde_json::Value> {
        self.send_command(
            "disasm",
            Some(json!({"address": address, "count": num_instructions})),
        )
    }

    /// Disassemble at `address`, disassembling first if no instruction is
    /// there yet. Returns `ok`/`landed` booleans plus the resulting
    /// instructions (up to `count`).
    pub fn disasm_at(&self, address: &str, count: Option<usize>) -> Result<serde_json::Value> {
        self.send_command(
            "disasm_at",
            Some(json!({"address": address, "count": count})),
        )
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

    pub fn function_set_noreturn(&self, target: &str, value: bool) -> Result<serde_json::Value> {
        self.send_command(
            "function_set_noreturn",
            Some(json!({"target": target, "value": value})),
        )
    }

    pub fn function_tag_add(&self, target: &str, tag_name: &str) -> Result<serde_json::Value> {
        self.send_command(
            "function_tag_add",
            Some(json!({"target": target, "tag_name": tag_name})),
        )
    }

    pub fn function_tag_remove(&self, target: &str, tag_name: &str) -> Result<serde_json::Value> {
        self.send_command(
            "function_tag_remove",
            Some(json!({"target": target, "tag_name": tag_name})),
        )
    }

    /// Tags on one function, or every tag definition in the program if
    /// `target` is `None`.
    pub fn function_tag_list(&self, target: Option<&str>) -> Result<serde_json::Value> {
        self.send_command("function_tag_list", Some(json!({"target": target})))
    }

    pub fn stats(&self) -> Result<serde_json::Value> {
        self.send_command("stats", None)
    }

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

    pub fn script_python(&self, code: &str) -> Result<serde_json::Value> {
        self.send_command("script_python", Some(json!({"code": code})))
    }

    pub fn script_java(&self, code: &str) -> Result<serde_json::Value> {
        self.send_command("script_java", Some(json!({"code": code})))
    }

    pub fn script_list(&self) -> Result<serde_json::Value> {
        self.send_command("script_list", None)
    }

    pub fn program_close(&self) -> Result<serde_json::Value> {
        self.send_command("program_close", None)
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

#[cfg(test)]
mod tests {
    use super::decompile_timeout_secs;

    #[test]
    fn decompile_timeout_defaults_to_unbounded() {
        // Avoid changing the process environment because this suite runs tests
        // concurrently. The assertion applies to the normal unset case.
        if std::env::var_os("GHIDRA_CLI_DECOMPILE_TIMEOUT").is_none() {
            assert_eq!(decompile_timeout_secs(), 0);
        }
    }
}
