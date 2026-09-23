use super::BridgeClient;
use anyhow::Result;
use serde_json::json;

pub struct MemoryBlockCreateRequest<'a> {
    pub name: &'a str,
    pub start: &'a str,
    pub size: i64,
    pub uninitialized: bool,
    pub fill: Option<u8>,
    pub permissions: &'a str,
    pub volatile: bool,
    pub overlay: Option<&'a str>,
}

impl BridgeClient {
    /// List memory blocks.
    pub fn memory_block_list(&self) -> Result<serde_json::Value> {
        self.send_command("memory_block_list", None)
    }

    /// Read every direct mapping before client-side row queries are applied.
    pub fn memory_file_mappings(
        &self,
        file_offset: Option<&str>,
        source_at: Option<&str>,
    ) -> Result<serde_json::Value> {
        let mut args = json!({});
        if let Some(file_offset) = file_offset {
            args["file_offset"] = json!(file_offset);
        }
        if let Some(source_at) = source_at {
            args["source_at"] = json!(source_at);
        }
        self.send_command("memory_file_mappings", Some(args))
    }

    pub fn memory_block_create(
        &self,
        args: MemoryBlockCreateRequest<'_>,
    ) -> Result<serde_json::Value> {
        let mut request = json!({
            "name": args.name,
            "start": args.start,
            "size": args.size,
            "uninitialized": args.uninitialized,
            "permissions": args.permissions,
            "volatile": args.volatile,
        });
        if let Some(fill) = args.fill {
            request["fill"] = json!(fill);
        }
        if let Some(overlay) = args.overlay {
            request["overlay"] = json!(overlay);
        }
        self.send_command("memory_block_create", Some(request))
    }

    pub fn memory_block_set(
        &self,
        block_start: &str,
        name: Option<&str>,
        permissions: Option<&str>,
        volatile: Option<bool>,
    ) -> Result<serde_json::Value> {
        let mut args = json!({"block_start": block_start});
        if let Some(name) = name {
            args["name"] = json!(name);
        }
        if let Some(permissions) = permissions {
            args["permissions"] = json!(permissions);
        }
        if let Some(volatile) = volatile {
            args["volatile"] = json!(volatile);
        }
        self.send_command("memory_block_set", Some(args))
    }

    pub fn memory_block_move(&self, block_start: &str, start: &str) -> Result<serde_json::Value> {
        self.send_command(
            "memory_block_move",
            Some(json!({"block_start": block_start, "start": start})),
        )
    }

    pub fn memory_block_delete(&self, block_start: &str) -> Result<serde_json::Value> {
        self.send_command(
            "memory_block_delete",
            Some(json!({"block_start": block_start})),
        )
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

    /// Define data at an address. With `force`, clears conflicting code/data
    /// units first instead of failing on them.
    pub fn define_data(
        &self,
        address: &str,
        type_name: &str,
        force: bool,
    ) -> Result<serde_json::Value> {
        self.send_command(
            "define_data",
            Some(json!({"address": address, "type_name": type_name, "force": force})),
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
