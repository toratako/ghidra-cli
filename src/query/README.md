# Query execution

`Query::from_options` parses the query before connecting to Ghidra.
`QueryPlan` then resolves the configured limit and splits the work into bridge
fetch arguments and a residual Rust query. `app::CommandResult` carries that
same residual query and effective page to standalone or batch output; output
does not rebuild them. The page is recorded before consuming a pushed offset,
so metadata describes the original selection.

The plan records each command adapter's fetch support: contains/paging, limit
only, or neither. A limit is sent only if the adapter forwards it and the
remaining row selection does not need a full fetch. Commands without fetch
limits retain their cap in Rust. Default caps use the same residual query as
explicit queries. Only row and graph commands with query options receive the
configured default; single values and their nested arrays are never paginated.

## Conservative list queries

| List | Server filter field |
|---|---|
| `function list` | `name` |
| `symbol list` | `name` |
| `type list` | `name` |
| `string list` | `value` |
| `find string PATTERN` | `value` (in addition to the positional pattern) |
| `comment list` | `text` |

Only a single `field~value` expression on the listed field is pushed down.
The bridge receives the literal value, never the filter DSL. Java `ListQuery`
applies locale-independent lowercase contains, then skips matching rows, then
caps returned rows, before constructing their JSON. Function tag/untagged
predicates and the `find string` pattern also run before offset. Rows keep the
handler's existing iterator order; comments at the same address but with different
types are distinct rows.

Server paging is enabled only without Rust sort/count and with either no filter
or the supported contains filter. Other filters, including `=`, `^`, `$`, regex,
numeric comparisons, compound expressions and other fields, remain wholly in
Rust. They require an uncapped fetch. A supported contains filter can still
reduce the transferred rows for sort/count, but its offset and limit stay in Rust.
Lists outside the table retain client-side offset and must fetch without a cap
when a client filter/sort/count/offset is requested.

The remaining pipeline is filter -> sort -> offset/limit -> count or fields.
The application renders the resulting JSON value. A pushed filter is checked
again in Rust; a pushed offset is removed
from the residual query. Projection never erases keys needed for sorting.

When omitted, the limit defaults to `default_limit`, including with no query
options, with projection only, or after filtering, sorting or offset.
CLI pagination uses `--skip N`; the bridge arguments and page metadata retain
`offset`. `--fields a,b` includes fields and `--exclude-fields a,b` excludes them;
these projection options are mutually exclusive. Projection leaves the
per-field descending prefix in `--sort=-size,name` independent.
Explicit `--limit 0` is unlimited. `--count` ignores the
configured limit but honors explicit offset/limit: it counts the selected page,
not a separate total. The wire envelope's `count` is the number of returned rows.

`graph calls` applies the residual query to its `nodes`, retaining the graph
object with `nodes`, `edges`, `node_count`, and `edge_count`. Edges remain in
bridge order and include all calls from the selected nodes, even when their
destinations are outside the selected page. Node IDs are matched before field
projection; counts reflect the returned nodes and edges. `--count` returns the
selected node count. An empty selection retains an empty graph object.
Standalone and batch queries share this processing and the same result envelope,
including when no query options are supplied.

`find bytes`, `find text`, and `find string` use this same limit contract,
without a separate fixed result cap. `find string` visits defined strings only;
its pattern and a pushed `value~...` filter are independent AND predicates.
It shares `StringQueries` with `string list`, including row fields
`address`, `value`, `char_length` (Unicode code points) and `byte_length`
(occupied Ghidra data bytes, potentially including terminators/padding).
`find constant` matches numeric Scalar operands before applying the same
limit-only fetch plan as `find instruction`. Its value/range and optional width
predicates run in Java; query filters, sorts, counts and offsets request all
matches for residual selection in Rust.
`find bytes --regex` applies its native Ghidra regex before the fetch cap;
residual selection still requests all matches.

`type uses` also uses limit-only fetching. Its `--kind` selects the declaration
iterators before matching, while row filters, sorting, offsets and counts require
an uncapped fetch. Results keep `target_type_path`, `kinds` and `scan` as context;
`scan.complete` concerns the database scan, not completeness of the displayed page.
There is no total count of unvisited declarations when the scan stops at its limit.

`disassemble`, with or without `--end`, and `function disassemble` also use
this contract: no independent instruction-count window caps the input before
filtering, sorting, offsetting, or counting. Plain limits are pushed to Java.
`listing define-code` returns a mutation receipt: `--end` bounds instruction creation,
and `default_limit` does not apply. Use `disassemble` for subsequent reads.

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
- Planner tests compare pushed and full-fetch results; routing tests check wire
  arguments and standalone/batch equivalence. `tests/readonly/query.rs` covers
  list/search paging, including Unicode samples under a Turkish JVM locale.
  Repeat these cross-runtime checks on toolchain upgrades: samples do not prove
  identical Rust/JDK casing tables. `strings.rs` covers code-point/occupied-byte
  lengths and both search predicates; `search_limits.rs` covers uncapped
  selection, batch output, and cancellation followed by a fresh request.

Deferred features and their reasons are in the
[server-side query plan](../../docs/PLAN.md#4-server-side-query-and-streaming).
