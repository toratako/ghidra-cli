use super::transport::long_op_timeout;
use super::BridgeClient;
use anyhow::Result;
use serde_json::json;

/// Native decompiler execution budget sent to Ghidra. Ghidra defines zero as
/// unbounded; that is the default because large, valid functions routinely take
/// longer than its historical 30-second background-analysis default.
fn decompile_timeout_secs() -> Result<u32> {
    match std::env::var("GHIDRA_CLI_DECOMPILE_TIMEOUT") {
        Ok(value) => parse_decompile_timeout_secs(&value),
        Err(std::env::VarError::NotPresent) => Ok(0),
        Err(error) => Err(anyhow::anyhow!(
            "Invalid GHIDRA_CLI_DECOMPILE_TIMEOUT: {error}"
        )),
    }
}

fn parse_decompile_timeout_secs(value: &str) -> Result<u32> {
    // Ghidra converts seconds to milliseconds with signed 32-bit arithmetic.
    const MAX_SECONDS: u32 = i32::MAX as u32 / 1000;
    value
        .trim()
        .parse::<u32>()
        .ok()
        .filter(|&seconds| seconds <= MAX_SECONDS)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "GHIDRA_CLI_DECOMPILE_TIMEOUT must be an integer from 0 to {}",
                MAX_SECONDS
            )
        })
}

impl BridgeClient {
    /// List functions. `tags` restricts to functions carrying ALL of the given
    /// tags (server-side filter); `untagged` restricts to functions with no tags.
    pub fn list_functions(
        &self,
        limit: Option<usize>,
        filter: Option<String>,
        tags: &[String],
        untagged: bool,
        offset: Option<usize>,
    ) -> Result<serde_json::Value> {
        self.send_command(
            "list_functions",
            Some(json!({
                "limit": limit,
                "filter": filter,
                "tags": tags,
                "untagged": untagged,
                "offset": offset,
            })),
        )
    }

    /// Decompile a function.
    pub fn decompile(
        &self,
        address: String,
        with_vars: bool,
        with_params: bool,
        with_jump_tables: bool,
    ) -> Result<serde_json::Value> {
        self.send_decompile_command(
            "decompile",
            json!({
                "address": address,
                "with_vars": with_vars,
                "with_params": with_params,
                "with_jump_tables": with_jump_tables,
            }),
        )
    }

    fn send_decompile_command(
        &self,
        command: &str,
        mut args: serde_json::Value,
    ) -> Result<serde_json::Value> {
        args["timeout_secs"] = json!(decompile_timeout_secs()?);
        self.send_command_with_timeout(command, Some(args), long_op_timeout())
    }

    /// List the current compiler specification's calling conventions.
    pub fn function_list_calling_conventions(&self) -> Result<serde_json::Value> {
        self.send_command("function_list_calling_conventions", None)
    }

    pub fn pcode_at(&self, address: &str) -> Result<serde_json::Value> {
        self.send_command("pcode_at", Some(json!({"address": address})))
    }

    pub fn pcode_function(&self, function: &str, high: bool) -> Result<serde_json::Value> {
        let args = json!({"function": function, "high": high});
        if high {
            self.send_decompile_command("pcode_function", args)
        } else {
            self.send_command("pcode_function", Some(args))
        }
    }

    /// Get cross-references to an address.
    pub fn xrefs_to(&self, address: String) -> Result<serde_json::Value> {
        self.send_command("xrefs_to", Some(json!({"address": address})))
    }

    /// Get cross-references from one address, or the whole containing function.
    pub fn xrefs_from(&self, address: String, function: bool) -> Result<serde_json::Value> {
        self.send_command(
            "xrefs_from",
            Some(json!({"address": address, "function": function})),
        )
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

    /// Set the return type, preserving uncommitted parameters through decompilation.
    pub fn function_set_return_type(
        &self,
        target: &str,
        return_type: &str,
    ) -> Result<serde_json::Value> {
        self.send_decompile_command(
            "function_set_return_type",
            json!({"target": target, "return_type": return_type}),
        )
    }

    pub fn function_set_noreturn(&self, target: &str, value: bool) -> Result<serde_json::Value> {
        self.send_command(
            "function_set_noreturn",
            Some(json!({"target": target, "value": value})),
        )
    }

    pub fn function_edit_var(
        &self,
        target: &str,
        var_name: &str,
        new_name: Option<&str>,
        type_name: Option<&str>,
    ) -> Result<serde_json::Value> {
        self.send_decompile_command(
            "function_edit_var",
            json!({
                "target": target,
                "var_name": var_name,
                "new_name": new_name,
                "type_name": type_name,
            }),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{decompile_timeout_secs, parse_decompile_timeout_secs};

    #[test]
    fn decompile_timeout_defaults_to_unbounded() {
        // Avoid changing the process environment because this suite runs tests
        // concurrently. The assertion applies to the normal unset case.
        if std::env::var_os("GHIDRA_CLI_DECOMPILE_TIMEOUT").is_none() {
            assert_eq!(decompile_timeout_secs().unwrap(), 0);
        }
    }

    #[test]
    fn decompile_timeout_rejects_invalid_or_overflowing_native_budgets() {
        for (text, expected) in [("0", 0), (" 47 ", 47), ("2147483", 2147483)] {
            assert_eq!(parse_decompile_timeout_secs(text).unwrap(), expected);
        }
        for text in [
            "",
            "-1",
            "1.5",
            "invalid",
            "2147484",
            "2147483647",
            "2147483648",
            "4294967295",
            "18446744073709551615",
        ] {
            assert!(parse_decompile_timeout_secs(text).is_err(), "{text}");
        }
    }
}
