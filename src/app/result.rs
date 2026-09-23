use crate::cli::{self, Commands};
use crate::query::{Page, Query};
use anyhow::Context;
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::collections::HashSet;

/// The command owns its result shape; payload keys never select a shape.
#[derive(Clone, Copy, Debug, Default)]
pub(super) enum ResultShape {
    #[default]
    Value,
    Rows {
        key: Option<&'static str>,
        context: &'static [&'static str],
    },
    Graph,
}

impl ResultShape {
    pub fn for_command(command: &Commands) -> Self {
        use cli::*;
        match command {
            Commands::Function(FunctionCommands::List(_)) => Self::rows("functions"),
            Commands::Function(FunctionCommands::Var(FunctionVarCommands::List(_))) => {
                Self::context(
                    "variables",
                    &["function", "address", "program", "modification"],
                )
            }
            Commands::Function(FunctionCommands::ListCallingConventions(_)) => {
                Self::rows("calling_conventions")
            }
            Commands::Function(FunctionCommands::Disasm(_)) | Commands::Disasm(_) => {
                Self::rows("instructions")
            }
            Commands::Strings(StringsCommands::List(_)) => Self::rows("strings"),
            Commands::Strings(StringsCommands::Refs(_)) => Self::context("results", &["pattern"]),
            Commands::Symbol(SymbolCommands::List(_) | SymbolCommands::Get(_)) => {
                Self::rows("symbols")
            }
            Commands::Symbol(SymbolCommands::Externals(_)) => Self::rows("externals"),
            Commands::Symbol(SymbolCommands::EntryPoints(_)) => Self::rows("entry_points"),
            Commands::Memory(MemoryCommands::Map(_)) => Self::rows("blocks"),
            Commands::Memory(MemoryCommands::FileMappings(_)) => Self::context(
                "mappings",
                &["unsupported_mappings", "file_offset", "source_at"],
            ),
            Commands::Data(DataCommands::List(_)) => Self::rows("items"),
            Commands::XRef(XRefCommands::To(_) | XRefCommands::From(_)) => Self::rows("xrefs"),
            Commands::Equate(EquateCommands::List(_)) => Self::rows("equates"),
            Commands::Namespace(NamespaceCommands::List(_)) => Self::rows("namespaces"),
            Commands::Type(TypeCommands::List(_)) => Self::rows("types"),
            Commands::Type(TypeCommands::Uses(_)) => {
                Self::context("uses", &["target_type_path", "kinds", "scan"])
            }
            Commands::Type(TypeCommands::Category(TypeCategoryCommands::List(_))) => {
                Self::context("categories", &["path"])
            }
            Commands::Tag(TagCommands::List(_)) => Self::rows("tags"),
            Commands::Analysis(AnalysisCommands::Option(AnalysisOptionCommands::List(_))) => {
                Self::rows("options")
            }
            Commands::Comment(CommentCommands::List(_)) => Self::rows("comments"),
            Commands::Comment(CommentCommands::Get(_)) => Self::context("comments", &["address"]),
            Commands::Bookmark(BookmarkCommands::List(_) | BookmarkCommands::Get(_)) => {
                Self::rows("bookmarks")
            }
            Commands::Graph(GraphCommands::Calls(_)) => Self::Graph,
            Commands::Graph(GraphCommands::Callers(_) | GraphCommands::Callees(_)) => {
                Self::context("calls", &["target"])
            }
            Commands::Find(FindCommands::AddressTables(_)) => Self::context(
                "results",
                &[
                    "detector",
                    "scope",
                    "ranges",
                    "pointer_size",
                    "endian",
                    "pointer_shift",
                    "min_entries",
                    "alignment",
                    "scan",
                ],
            ),
            Commands::Find(_) => Self::rows("results"),
            Commands::Program(ProgramCommands::List(_)) => {
                Self::context("programs", &["has_current_program", "current_program_name"])
            }
            Commands::Program(ProgramCommands::ListRelocations(_)) => Self::rows("relocations"),
            Commands::Program(ProgramCommands::Context(ProgramContextCommands::List(_))) => {
                Self::rows("registers")
            }
            Commands::Program(ProgramCommands::Context(ProgramContextCommands::Get(_))) => {
                Self::context("ranges", &["register", "bit_length", "start", "end"])
            }
            Commands::Script(ScriptCommands::List) => Self::rows("scripts"),
            Commands::Project(args) if matches!(args.command, ProjectCommands::List) => {
                Self::Rows {
                    key: None,
                    context: &[],
                }
            }
            Commands::Project(_)
            | Commands::Graph(GraphCommands::Cfg(_))
            | Commands::Program(_)
            | Commands::Function(_)
            | Commands::Symbol(_)
            | Commands::XRef(_)
            | Commands::Equate(_)
            | Commands::Namespace(_)
            | Commands::Bookmark(_)
            | Commands::Memory(_)
            | Commands::Vtable(_)
            | Commands::Data(_)
            | Commands::Listing(_)
            | Commands::Type(_)
            | Commands::Tag(_)
            | Commands::Pcode(_)
            | Commands::Analysis(_)
            | Commands::Comment(_)
            | Commands::Decompile(_)
            | Commands::Script(_)
            | Commands::Batch(_)
            | Commands::Config(_)
            | Commands::Doctor { .. }
            | Commands::Bridge(_)
            | Commands::Job(_) => Self::Value,
        }
    }

    fn rows(key: &'static str) -> Self {
        Self::context(key, &[])
    }

    fn context(key: &'static str, context: &'static [&'static str]) -> Self {
        Self::Rows {
            key: Some(key),
            context,
        }
    }

    pub fn supports_paging(self) -> bool {
        matches!(self, Self::Rows { .. } | Self::Graph)
    }
}

/// Canonical result shared by ordinary JSON, batch entries, and presentation.
#[derive(Serialize)]
pub(super) struct CommandOutput {
    pub data: Value,
    #[serde(skip_serializing_if = "Map::is_empty")]
    pub meta: Map<String, Value>,
    #[serde(skip)]
    pub is_list: bool,
    #[serde(skip)]
    pub is_count: bool,
}

impl CommandOutput {
    pub fn prepare(
        mut value: Value,
        shape: ResultShape,
        query: Option<&Query>,
        page: Option<Page>,
    ) -> anyhow::Result<Self> {
        let mut meta = Map::new();
        if let Some(page) = page {
            meta.insert("offset".into(), json!(page.offset));
            meta.insert("limit".into(), json!(page.limit));
        }
        let is_count = query.is_some_and(|query| query.count_only);
        let data = match shape {
            ResultShape::Value => project(value, query)?,
            ResultShape::Rows { key, context } => {
                for &key in context {
                    if let Some(value) = value.get_mut(key) {
                        meta.insert(key.into(), value.take());
                    }
                }
                let rows = match key {
                    Some(key) => value
                        .get_mut(key)
                        .with_context(|| format!("Missing result rows: {key}"))?
                        .take(),
                    None => value,
                };
                let Value::Array(rows) = rows else {
                    anyhow::bail!("Expected an array of result rows");
                };
                let data = match query {
                    Some(query) => query.apply(rows)?,
                    None => Value::Array(rows),
                };
                if !is_count {
                    meta.insert(
                        "returned".into(),
                        json!(data
                            .as_array()
                            .context("Expected an array of result rows")?
                            .len()),
                    );
                }
                data
            }
            ResultShape::Graph => {
                let nodes = select(value["nodes"].take(), query)?;
                if is_count {
                    json!(nodes.len())
                } else {
                    // Match outgoing edges before projection can remove node IDs.
                    let ids: HashSet<_> = nodes
                        .iter()
                        .filter_map(|node| node["id"].as_str())
                        .collect();
                    let edges = value["edges"]
                        .as_array()
                        .context("Missing graph edges")?
                        .iter()
                        .filter(|edge| edge["from"].as_str().is_some_and(|id| ids.contains(id)))
                        .cloned()
                        .collect::<Vec<_>>();
                    value["node_count"] = json!(nodes.len());
                    value["edge_count"] = json!(edges.len());
                    value["edges"] = Value::Array(edges);
                    value["nodes"] = Value::Array(project_rows(nodes, query)?);
                    value
                }
            }
        };
        Ok(Self {
            data,
            meta,
            is_list: matches!(shape, ResultShape::Rows { .. }) && !is_count,
            is_count,
        })
    }

    pub fn rows(&self) -> &[Value] {
        if self.is_list {
            self.data.as_array().expect("prepared list result")
        } else {
            std::slice::from_ref(&self.data)
        }
    }
}

fn select(value: Value, query: Option<&Query>) -> anyhow::Result<Vec<Value>> {
    let Value::Array(rows) = value else {
        anyhow::bail!("Expected an array of result rows");
    };
    Ok(match query {
        Some(query) => query.select_rows(rows)?,
        None => rows,
    })
}

fn project_rows(rows: Vec<Value>, query: Option<&Query>) -> anyhow::Result<Vec<Value>> {
    Ok(
        match query.and_then(|query| query.fields.as_ref().map(|fields| (query, fields))) {
            Some((query, fields)) => query.select_fields(&rows, fields)?,
            None => rows,
        },
    )
}

fn project(value: Value, query: Option<&Query>) -> anyhow::Result<Value> {
    Ok(project_rows(vec![value], query)?
        .pop()
        .expect("one result value"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::{FetchSupport, FieldSelector, QueryPlan};

    #[test]
    fn lists_preserve_context_and_page_after_projection_and_pushed_offset() {
        let plan = QueryPlan::new(
            Some(Query {
                fields: Some(FieldSelector::include(vec!["name".into()])),
                offset: Some(4),
                limit: Some(1),
                ..Query::default()
            }),
            Some(1000),
            FetchSupport::Paged("name"),
        );
        assert_eq!(plan.fetch.offset, Some(4));
        for extra in [false, true] {
            let mut value = json!({"items": [{"name": "main", "size": 12}], "target": "root"});
            if extra {
                value["additional_context"] = json!(true);
            }
            let result = CommandOutput::prepare(
                value,
                ResultShape::context("items", &["target"]),
                plan.post.as_ref(),
                Some(plan.page),
            )
            .unwrap();
            assert_eq!(
                serde_json::to_value(result).unwrap(),
                json!({
                    "data": [{"name": "main"}],
                    "meta": {"target": "root", "returned": 1, "offset": 4, "limit": 1}
                })
            );
        }
    }

    #[test]
    fn empty_lists_and_counts_keep_context_without_inventing_totals() {
        let shape = ResultShape::context("comments", &["address"]);
        let value = json!({"comments": [], "address": "ram:0x1000"});
        let result =
            CommandOutput::prepare(value.clone(), shape, None, Some(Page::default())).unwrap();
        assert_eq!(
            serde_json::to_value(result).unwrap(),
            json!({
                "data": [], "meta": {"address": "ram:0x1000", "returned": 0, "offset": 0, "limit": null}
            })
        );
        let query = Query {
            count_only: true,
            ..Query::default()
        };
        let result =
            CommandOutput::prepare(value, shape, Some(&query), Some(Page::default())).unwrap();
        assert_eq!(
            serde_json::to_value(result).unwrap(),
            json!({
                "data": 0, "meta": {"address": "ram:0x1000", "offset": 0, "limit": null}
            })
        );
    }

    #[test]
    fn values_keep_nested_data_and_scalar_types_without_empty_metadata() {
        for value in [
            json!({"status": "deleted", "count": 2, "before": {"items": [1, 2]}, "saved": true}),
            json!({"nodes": [1, 2], "edges": [], "warnings": ["incomplete"]}),
            json!(["config", "array"]),
            json!(7),
            json!("text"),
            Value::Null,
        ] {
            let result =
                CommandOutput::prepare(value.clone(), ResultShape::Value, None, None).unwrap();
            assert!(!result.is_list);
            assert_eq!(result.rows(), std::slice::from_ref(&value));
            assert_eq!(
                serde_json::to_value(result).unwrap(),
                json!({"data": value})
            );
        }
    }
}
