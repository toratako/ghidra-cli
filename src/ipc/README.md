# IPC

All CLI-to-bridge command traffic uses `BridgeClient` in [client.rs](client.rs).
Typed adapters construct arguments; unsupported adapters can use
`send_command(command, args)` directly. [protocol.rs](protocol.rs) defines the
wire structs; [client/transport.rs](client/transport.rs) owns transport and its
tests. Raw TCP elsewhere is only a liveness probe.

## Connection and timeout boundaries

Each request uses a fresh localhost TCP connection for one newline-terminated
JSON request and response. Socket handlers run independently of the serialized
Ghidra program lane; see [Java execution ownership](../ghidra/scripts/ghidracli/README.md).

Retry transient connection failures with backoff only **before sending**; replaying
a sent mutation could duplicate it. Read waits include time in the program queue.
The write timeout is 30s; configurable read/connect/long-operation budgets are in
[the runtime reference](../../docs/runtime.md). Decompiler execution timeout stays
in the shared decompiler adapter because it is a Ghidra parameter, not a socket budget.
`decompile`, high `pcode_function`, and `function_edit_var` share the native budget
and long-operation socket wait. Their `timeout_secs` argument defaults to zero
(unbounded); numeric integers through 2,147,483 seconds are accepted. Reject larger
values before Ghidra's signed-int seconds-to-milliseconds conversion can overflow.
EOF without a reply is an error; read timeouts exit 75 without cancelling the job.
Shutdown uses the caller's remaining total deadline for connect, write, and read;
it must not fall back to an independent generic socket timeout. The lifecycle
caller also budgets lock acquisition and process exit, preserves the typed
timeout error, and retains live discovery on failure.
`BridgeClient` sends `shutdown_wait`, advertised by `bridge_info.durable_shutdown`,
to receive final save failures as errors. The request waits outside the bounded
program queue and leaves controls available. Save failure retains the JVM and
reopens the queue for recovery.

## Wire format

```json
{"command":"list_functions","args":{"limit":100}}
{"status":"success","data":{"functions":[]},"message":null}
```

Request `command` is required; optional `args` is omitted when `None`.
Response `data` and `message` are optional. The CLI unwraps the response and
chooses its output format; the bridge always sends compact JSON.

`list_functions`, `list_strings`, `symbol_list`, `type_list`, `comment_list`, and
`find_string` accept literal `filter`, `offset`, and `limit` arguments. Filters are
case-insensitive contains on their documented string field; the DSL stays in
Rust. Offset counts matching rows before limit; missing/null/zero limit is
unlimited and missing/null offset is zero. Numeric page arguments must be
integers in `0..=9223372036854775807`; invalid values fail instead of narrowing
to Java `int`. Responses retain their array and returned-row `count` envelope.
See [query planning](../query/README.md) for when these arguments may be pushed.
The CLI and running Java bridge must use the same build.

`find_string` also accepts `pattern`, a case-insensitive literal substring of
the decoded string value. Missing/null/empty patterns match all defined strings
(the CLI requires a positional pattern; pass `""` for all values). Both `pattern`
and `filter` must match before offset/limit are applied. `list_strings` and
`find_string` share row fields `address`, `value`, `char_length` (Unicode code
points), and `byte_length` (Ghidra data's occupied bytes, including any defined
terminators/padding). Their response array keys are `strings` and `results`,
respectively.
`BridgeClient::find_string_page` exposes filter/offset/limit, while
`find_string` and `find_string_with_limit` retain their existing defaults.

`tag_get` accepts an exact, case-sensitive `name` and returns one tag object:
`{name, comment, use_count}`. `use_count` is Ghidra's total usage, including
external functions when present. Membership queries use `list_functions` with
`tags`, which lists non-external functions.

`list_imports`, `list_exports`, `tag_list`, `graph_calls`,
`graph_callers`, `graph_callees`, and `find_instruction` accept `limit` only in
`0..=2147483647`. Graph `depth` uses the same checked range and defaults to 1.
Missing/null limits default to zero (unlimited); fractional, nonnumeric and
overflowing values fail. The CLI validates these limits before bridge work,
including when filtering leaves the limit in Rust. Other long-based paging
arguments retain their existing range.

`graph_callers` and `graph_callees` take `function`, `depth`, and `limit` and
return `{target, calls, count}`. Each call has `caller`, nullable `caller_address`,
`callee`, `callee_address`, `call_site`, `destination`, `via`, `type`, and `depth`. Function names
are null when undefined; `callee_address` remains the known destination in that
case, otherwise it is the canonical function entry. `destination` is the resolved
landing address, retaining interior offsets. `via` is the original
reference destination and `type` is its Ghidra reference type. Immediate rows have
depth zero. Callers accepts undefined destination addresses; callees needs a
function body. `graph_calls` retains its nodes/edges envelope and node-based query
contract; its edges carry the same call fields except depth, plus `from`/`to` IDs.
Edges to external or undefined destinations need not have a node in the response.

`disasm` uses the checked `limit` argument; missing/null/zero means unlimited.
The CLI resolves `default_limit` before sending these requests.

`define_code` accepts `target` and optional inclusive `end`, both exact names or
explicit addresses. Bounds are validated before mutation. It follows native
Ghidra code flow but confines complete instructions and delay-slot groups to the
requested range when `end` is given. It does not run auto-analysis. The
receipt contains `address`, `end`, `status` (`defined`/`unchanged`/`failed`),
`already_defined`, `changed`, `ok`, and `landed`, without instruction rows.
No definition at the target is an error with the receipt retained in detail.
Query arguments are rejected. The optional `clear_range.disasm_at` argument
does not use this bounded operation. Clearing and its optional redisassembly are
atomic together; a failed redisassembly receipt has
`status: "failed"` in the error detail. Failure rolls back the clearing.

`bridge_info.auto_save: true` advertises saving before successful program
responses. `program_save` retries pending saves without restarting. A save failure
returns `error` with `detail.save_failed: true`, `saved: false`, and the original
`command_response`; do not replay the edit. The first save failure in a request
is returned without an implicit retry, leaving pending edits for explicit save.

Ordinary requests are atomic: error or cancellation rolls back all their Program
changes and adds `detail.rolled_back: true`; cancellation also adds
`detail.cancelled: true`. Earlier requests remain intact, including earlier lines
in a batch. Rollback does not flush pending edits from an earlier save failure.
The non-atomic exceptions are `analyze`, `script_run`, `import`, `program_export`,
`open_program`, `program_close`, `program_save`, and `program_delete`. Errors from
those requests can include `detail.partial_changes_saved: true` when retained
Program changes were saved; external project/file effects are outside rollback.

Transaction ownership failures use `detail.transaction_failed: true`, without
claiming rollback. An ordinary request is rejected before execution if a foreign
transaction is already active; that transaction and its edits remain untouched.
If native code leaves a child open inside an atomic request, the bridge aborts
its owned root entry and leaves rollback pending until the child's owner closes
it. The response retains `command_response` for diagnosis, but reports neither
`rolled_back` nor a save; those failed-request edits cannot be committed.
The owning script must resolve the outstanding transaction; recovery scripts
are still accepted.

`bridge_info.atomic_edits: true` advertises this request rollback contract. The CLI
requires it alongside `auto_save` and `explicit_addresses` before program dispatch;
a missing capability fails with explicit bridge-restart guidance, without sending
the program command or automatically upgrading the bridge. Explicit `program_save`
uses the direct recovery path and remains available before restarting an older
bridge with pending edits.

`xrefs_from` reads references from the exact resolved `address`. With `function: true`,
it resolves the containing function and reads its full body, including disjoint ranges.
`string_refs` takes `pattern`, a case-insensitive substring of defined string values.

`find_text` accepts non-empty `text`, optional `encoding` (a Java charset name,
default `utf-8`), and the checked `limit` used by `find_bytes`/`find_string`.
Encoding errors fail rather than substituting replacement bytes. It returns
`{"results":[{"address":"...","byte_length":4,"encoding":"UTF-8"}],"count":1}`.
Matches are exact byte sequences in program memory, including overlaps; rows
identify the match start without extracting surrounding text. `find_string`
searches defined strings only.

`find_bytes_regex` accepts non-empty `pattern` (Java byte regex syntax) and the
same checked `limit`. It returns
`{"results":[{"address":"0x1000","byte_length":6}],"count":1}`.
The bridge invokes Ghidra's native memory search over loaded, initialized memory;
it does not decode text. Invalid patterns and encountered zero-length matches
fail. Native buffering and overlap semantics apply. Cancellation is checked
after the native search, which otherwise returns partial results.

`bridge_info.explicit_addresses: true` advertises strict address parsing and
canonical address output. Before program dispatch, the CLI rejects a bridge
without this capability and requests an explicit restart; it never downgrades
address interpretation.

Address strings require `0x`/`0X` for every numeric colon component:
`0x401000`, `overlay:0x1000`, or `ram:0x1234:0x0005`. Segmented output always
includes the space name so numeric-looking registered space names cannot make
the result ambiguous. Unqualified `0x1234:0x0005` is segmented input only when
its first component is not a registered space name. Word addresses preserve
their optional `.byte` remainder. Address output uses the same syntax and
retains spaces. Name-or-address targets resolve every unprefixed token as an
exact name, including bare hex and `FUN_...`;
malformed explicit addresses never fall back to names. Address-only arguments
also enforce this contract for direct bridge requests. Offsets, counts, and
byte patterns retain their separate numeric formats.

`clear_range` requires canonical endpoints: colon-containing values start with
a registered space name, including for the default segmented space. Both
endpoints must belong to the same space and form an ascending inclusive range.

Symbol mutations require a non-empty `targets` array of snapshots resolved
through `symbol_get_by_name`. Each snapshot includes a stable symbol ID and
is revalidated before any mutation; stale or duplicate selections fail.
`symbol_get` accepts exact names or explicit addresses.
Failed multi-symbol deletion reports `attempted_deleted`, `failed`, and
`not_attempted` in detail. These are attempted-work diagnostics; `deleted` and
the committed `count` appear only on success.

| Response status | Client result |
|---|---|
| `success` | `data`, or `{}` if absent |
| `error` | Error with `message` and available structured detail |
| `shutdown` | `{"status":"shutdown"}` |
| Other | Protocol error |
