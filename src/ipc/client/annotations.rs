use super::BridgeClient;
use anyhow::Result;
use serde_json::json;

impl BridgeClient {
    /// List Ghidra external symbols.
    pub fn symbol_externals(&self, limit: Option<usize>) -> Result<serde_json::Value> {
        self.send_command("symbol_externals", Some(json!({"limit": limit})))
    }

    /// List Ghidra external entry points.
    pub fn symbol_entry_points(&self, limit: Option<usize>) -> Result<serde_json::Value> {
        self.send_command("symbol_entry_points", Some(json!({"limit": limit})))
    }

    pub fn symbol_list(
        &self,
        limit: Option<usize>,
        filter: Option<&str>,
        offset: Option<usize>,
    ) -> Result<serde_json::Value> {
        self.send_command(
            "symbol_list",
            Some(json!({"limit": limit, "filter": filter, "offset": offset})),
        )
    }

    pub fn symbol_get(&self, name: &str) -> Result<serde_json::Value> {
        self.send_command("symbol_get", Some(json!({"name": name})))
    }

    /// Resolve exact symbol names, including names beginning with 0x; symbol_get
    /// reserves explicit address syntax instead.
    pub fn symbol_get_by_name(&self, name: &str) -> Result<serde_json::Value> {
        self.send_command("symbol_get_by_name", Some(json!({"name": name})))
    }

    pub fn symbol_create_label(&self, address: &str, name: &str) -> Result<serde_json::Value> {
        self.send_command(
            "symbol_create_label",
            Some(json!({"address": address, "name": name})),
        )
    }

    /// Mutate only the stable symbol snapshots returned by symbol_get_by_name.
    pub fn symbol_delete_targets(
        &self,
        name: &str,
        targets: &[serde_json::Value],
    ) -> Result<serde_json::Value> {
        self.send_command(
            "symbol_delete",
            Some(json!({"name": name, "targets": targets})),
        )
    }

    pub fn symbol_rename_targets(
        &self,
        old_name: &str,
        new_name: &str,
        targets: &[serde_json::Value],
    ) -> Result<serde_json::Value> {
        self.send_command(
            "symbol_rename",
            Some(json!({"old_name": old_name, "new_name": new_name, "targets": targets})),
        )
    }

    pub fn type_list(
        &self,
        limit: Option<usize>,
        filter: Option<&str>,
        offset: Option<usize>,
    ) -> Result<serde_json::Value> {
        self.send_command(
            "type_list",
            Some(json!({"limit": limit, "filter": filter, "offset": offset})),
        )
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

    /// Get a function tag's name, comment, and use count.
    pub fn tag_get(&self, name: &str) -> Result<serde_json::Value> {
        self.send_command("tag_get", Some(json!({"name": name})))
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

    pub fn bookmark_list(&self) -> Result<serde_json::Value> {
        self.send_command("bookmark_list", None)
    }

    pub fn bookmark_get(&self, address: &str) -> Result<serde_json::Value> {
        self.send_command("bookmark_get", Some(json!({"address": address})))
    }

    pub fn comment_list(
        &self,
        limit: Option<usize>,
        filter: Option<&str>,
        offset: Option<usize>,
    ) -> Result<serde_json::Value> {
        self.send_command(
            "comment_list",
            Some(json!({"limit": limit, "filter": filter, "offset": offset})),
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

    pub fn comment_delete(
        &self,
        address: &str,
        comment_type: Option<&str>,
        all: bool,
    ) -> Result<serde_json::Value> {
        self.send_command(
            "comment_delete",
            Some(json!({"address": address, "comment_type": comment_type, "all": all})),
        )
    }
}
