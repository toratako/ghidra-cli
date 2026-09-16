# Query execution

`Query::from_options` parses the query before connecting to Ghidra.
`QueryPlan` then resolves the configured limit and splits the work into bridge
fetch arguments and a residual Rust query. `app::CommandResult` carries that
same residual query to standalone or batch output; output does not rebuild it.

The plan records each command adapter's fetch support: contains/paging, limit
only, or neither. A limit is sent only if the adapter forwards it and the
remaining row selection does not need a full fetch. Commands without fetch
limits retain their cap in Rust. With no explicit query options, the default
cap truncates the response's row array and updates its count while preserving
the batch envelope; it does not truncate nested fields of a single object.

## Conservative list queries

| List | Server filter field |
|---|---|
| `function list`, `query functions`, `dump functions` | `name` |
| `symbol list` | `name` |
| `type list` | `name` |
| `strings list`, `query strings`, `dump strings` | `value` |
| `comment list` | `text` |

Only a single `field~value` expression on the listed field is pushed down.
The bridge receives the literal value, never the filter DSL. Java `ListQuery`
applies locale-independent lowercase contains, then skips matching rows, then
caps returned rows, before constructing their JSON. Function tag/untagged
predicates also run before offset. Rows keep the handler's existing iterator
order; comments at the same address but with different types are distinct rows.

Server paging is enabled only without Rust sort/count and with either no filter
or the supported contains filter. Other filters, including `=`, `^`, `$`, regex,
numeric comparisons, compound expressions and other fields, remain wholly in
Rust. They require an uncapped fetch. A supported contains filter can still
reduce the transferred rows for sort/count, but its offset and limit stay in Rust.
Lists outside the table retain client-side offset and must fetch without a cap
when a client filter/sort/count/offset is requested.

The remaining pipeline is filter -> sort -> offset/limit -> count or fields ->
format. A pushed filter is checked again in Rust; a pushed offset is removed
from the residual query. Projection never erases keys needed for sorting.

When omitted, the limit defaults to `default_limit`, including with no query
options, with projection only, or after filtering, sorting or offset.
Explicit `--limit 0` is unlimited. `--count` ignores the
configured limit but honors explicit offset/limit: it counts the selected page,
not a separate total. The wire envelope's `count` is the number of returned rows.
Batch row selection and output formats retain their existing behavior.

`find bytes`, both `find string` search paths, and `find interesting` use this
same limit contract, without separate 100/50-result caps. `find interesting`
still scans and ranks candidates before limiting its results. Raw string
search remains a fallback when no defined string matches.

## Boundaries and validation

- Paging and predicates run on the existing Ghidra program lane using the active
  `ProgramSession`. Iterator loops check its current cancellation monitor.
- This reduces JSON generation and transfer, not necessarily database scans.
  Offset still scans from the start; rare matches may require a complete scan.
  There is no snapshot across separate page requests; intervening edits can
  shift their boundaries.
- There is no query-specific capability negotiation, restart or old-server
  fallback. CLI and bridge must be updated together; see
  [upgrade instructions](../../docs/runtime.md#upgrading).
- Java and Rust lowercase some Unicode contexts differently (e.g. `AΣ_A`),
  so contains pushdown can miss matches or shift pages. This known limitation
  is expected to have little impact on typical ASCII-based RE queries.
- Planner tests compare pushed and full-fetch results across filters, sort,
  count, projection, limits and offsets. Routing tests cover actual wire arguments
  and standalone/batch equivalence. `tests/readonly/query.rs` checks all five
  handlers and aliases against full rows, including Unicode samples under a
  Turkish JVM locale, tag predicates, comment types, empty pages and numeric bounds.
  These samples do not establish identical Unicode casing tables across every
  Rust/JDK release; repeat the cross-runtime checks when upgrading toolchains.
- `tests/readonly/search_limits.rs` exercises searches with 160 matches, client
  default caps, complete counts/selection, batch output, and cancellation of an
  uncapped dense byte search followed by a fresh request.

Deferred features and their reasons are in the
[server-side query plan](../../docs/PLAN.md#4-server-side-query-and-streaming).
