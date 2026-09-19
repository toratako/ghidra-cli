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
in its command adapter because it is a Ghidra parameter, not a socket budget.
EOF without a reply is an error; read timeouts exit 75 without cancelling the job.
Shutdown uses the caller's remaining total deadline for connect, write, and read;
it must not fall back to an independent generic socket timeout. The lifecycle
caller also budgets lock acquisition and process exit, preserves the typed
timeout error, and retains live discovery on failure.
`BridgeClient` sends `shutdown_wait`, advertised by `bridge_info.durable_shutdown`,
to receive final save failures as errors. Legacy `shutdown` only acknowledges
drain acceptance and cannot confirm saving; clients must not use it as a fallback.
The new request waits outside the bounded program queue and leaves controls
available. Save failure retains the JVM and reopens the queue for recovery.

## Wire format

```json
{"command":"list_functions","args":{"limit":100}}
{"status":"success","data":{"functions":[]},"message":null}
```

Request `command` is required; optional `args` is omitted when `None`.
Response `data` and `message` are optional. The CLI unwraps the response and
chooses its output format; the bridge always sends compact JSON.

`list_functions`, `list_strings`, `symbol_list`, `type_list`, and `comment_list`
accept literal `filter`, `offset`, and `limit` arguments. Filters are
case-insensitive contains on their documented string field; the DSL stays in
Rust. Offset counts matching rows before limit; missing/null/zero limit is
unlimited and missing/null offset is zero. Numeric page arguments must be
integers in `0..=9223372036854775807`; invalid values fail instead of narrowing
to Java `int`. Responses retain their array and returned-row `count` envelope.
See [query planning](../query/README.md) for when these arguments may be pushed.
This change requires a matching CLI and Java bridge; it adds no old-bridge
compatibility path.

`list_imports`, `list_exports`, `tag_list`, `tag_get`, `graph_calls`,
`graph_callers`, `graph_callees`, and `find_instruction` accept `limit` only in
`0..=2147483647`. Graph `depth` uses the same checked range and defaults to 1.
Missing/null limits default to zero (unlimited); fractional, nonnumeric and
overflowing values fail. The CLI validates these limits before bridge work,
including when filtering leaves the limit in Rust. Other long-based paging
arguments retain their existing range.

`disasm` uses the checked `limit` argument; missing/null/zero means unlimited.
The CLI resolves `default_limit` before sending these requests. The old request
argument `count` is rejected. Update the CLI and restart the bridge together:
an older bridge would ignore `limit` and apply its old fixed instruction count.

`define_code` accepts `target` and optional inclusive `end`, both exact names or
explicit addresses. Bounds are validated before mutation. It follows native
Ghidra code flow but confines complete instructions and delay-slot groups to the
requested range when `end` is given. It does not run auto-analysis. The
receipt contains `address`, `end`, `status` (`defined`/`unchanged`/`failed`),
`already_defined`, `changed`, `ok`, and `landed`, without instruction rows.
No definition at the target is an error with the receipt retained in detail.
The old `disasm_at` command is removed; `limit`, `count`, and other query
arguments are rejected. The distinct wire name prevents an old bridge from
silently ignoring bounds. The optional `clear_range.disasm_at` argument is
unchanged and does not use this bounded operation.

`bridge_info.auto_save: true` advertises saving before successful program
responses. `program_save` retries pending saves without restarting. A save failure
returns `error` with `detail.save_failed: true`, `saved: false`, and the original
`command_response`; do not replay the edit. Errors with retained, saved changes
include `detail.partial_changes_saved: true`.

`find_text` accepts non-empty `text`, optional `encoding` (a Java charset name,
default `utf-8`), and the checked `limit` used by `find_bytes`/`find_string`.
Encoding errors fail rather than substituting replacement bytes. It returns
`{"results":[{"address":"...","byte_length":4,"encoding":"UTF-8"}],"count":1}`.
Matches are exact byte sequences in program memory, including overlaps; rows
identify the match start without extracting surrounding text. `find_string`
now searches defined strings only. Update the bridge with the CLI to remove
the old implicit raw-memory fallback.

`find_bytes_regex` accepts non-empty `pattern` (Java byte regex syntax) and the
same checked `limit`. It returns
`{"results":[{"address":"0x1000","byte_length":6}],"count":1}`.
The bridge invokes Ghidra's native memory search over loaded, initialized memory;
it does not decode text. Invalid patterns and encountered zero-length matches
fail. Native buffering and overlap semantics apply. Cancellation is checked
after the native search, which otherwise returns partial results. The distinct
wire command prevents older bridges from treating a regex as literal hex.

`bridge_info.explicit_addresses: true` advertises strict address parsing and
canonical address output. Before program dispatch, the CLI rejects a bridge
without this capability and requests an explicit restart; it never downgrades
address interpretation. This check precedes compatibility recovery.

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

Symbol mutations resolve name snapshots through `symbol_get_by_name`.
`symbol_get` accepts exact names or explicit addresses; neither operation
performs legacy bare-hex or generated-name address inference.

| Response status | Client result |
|---|---|
| `success` | `data`, or `{}` if absent |
| `error` | Error with `message` and available structured detail |
| `shutdown` | `{"status":"shutdown"}` |
| Other | `data`, or `{}` if absent |
