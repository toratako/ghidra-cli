# IPC

All CLI-to-bridge command traffic uses `BridgeClient` in [client.rs](client.rs).
Typed adapters construct arguments; unsupported adapters can use
`send_command(command, args)` directly. [protocol.rs](protocol.rs) defines the
wire structs; [client/transport.rs](client/transport.rs) owns transport, with tests
in [client/transport/tests.rs](client/transport/tests.rs). Raw TCP elsewhere is
only a liveness probe.

Typed adapters remain methods on `BridgeClient`, grouped under `client/`:
`functions.rs` owns function/decompiler, p-code, xref and graph requests;
`memory.rs` owns memory and instruction operations; `annotations.rs` owns
symbols, types, tags, bookmarks and comments; `program.rs` owns program lifecycle
and analysis; `search.rs` owns strings and searches; `scripts.rs` owns scripts.

`graph_cfg` and high `pcode_function` accept positive `max_nodes` and `max_edges`
within the signed 32-bit range, defaulting to 1,000 and 4,000. Their structured
payloads carry result-scoped IDs, provenance, limit units and completion metadata.
Node and edge limits apply across the payload's collections; inverse High IR
references share the underlying relationship's edge cost. Omitted references
remain distinguishable from unresolved ones. Raw p-code keeps its instruction
listing contract.

## Connection and timeout boundaries

Each request uses a fresh localhost TCP connection for one newline-terminated
JSON request and response. Socket handlers run independently of the serialized
Ghidra program lane; see [Java execution ownership](../ghidra/scripts/ghidracli/README.md).

Retry transient connection failures with backoff only **before sending**; replaying
a sent mutation could duplicate it. Read waits include time in the program queue.
The write timeout is 30s; configurable read/connect/long-operation budgets are in
[the runtime reference](../../docs/runtime.md). Decompiler execution timeout stays
in the shared decompiler adapter because it is a Ghidra parameter, not a socket budget.
`decompile`, high `pcode_function`, `function_var_list/get/set`, and
`function_set_return_type` share the native budget and long-operation socket wait.
Their `timeout_secs` argument defaults to zero (unbounded); numeric integers
through 2,147,483 seconds are accepted. Reject larger
values before Ghidra's signed-int seconds-to-milliseconds conversion can overflow.
EOF, I/O failures after sending begins, malformed replies, and invalid response
statuses have a typed unknown outcome and must stop batches without replay.
Read timeouts exit 75 without cancelling the job; other unknown outcomes exit 1.
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
chooses its output format; the bridge always sends compact JSON. `success`
unwraps to `data` or `{}`; `error` retains message and structured detail;
`shutdown` becomes `{"status":"shutdown"}`. Other statuses are protocol errors.

The [paged list adapters](../query/README.md#conservative-list-queries) accept
literal `filter`, `offset`, and `limit`; the filter DSL stays in Rust. Offset
counts matching rows before limit. Missing/null/zero limit is unlimited;
missing/null offset is zero. Page arguments must be integers in
`0..=9223372036854775807`, never narrowed to Java `int`. Responses retain their
array and returned-row `count`. CLI and bridge must use the same build.

`find_string` also accepts `pattern`, a case-insensitive literal substring of
the decoded string value. Missing/null/empty patterns match all defined strings
(the CLI requires a positional pattern; pass `""` for all values). Both `pattern`
and `filter` must match before offset/limit are applied. `list_strings` and
`find_string` share row fields `address`, `value`, `char_length` (Unicode code
points), and `byte_length` (Ghidra data's occupied bytes, including any defined
terminators/padding). Their response array keys are `strings` and `results`,
respectively.

`analysis_run` uses the long-operation wait and the Program's saved settings.
Omitting mode arguments requests full analysis; paired inclusive `start`/`end`
addresses in the same space request range analysis; `pending: true` requests
only the live queue.
Range and pending arguments are mutually exclusive. A range must intersect
Program memory; empty intersections fail before scheduling. It seeds reanalysis,
not a limit on affected addresses, and can also drain existing queued work.
Pending work is not persisted and is discarded on cancellation, close, or restart;
an empty queue does not become a full analysis request.

Analysis results retain `program`, `function_count`, and `status: "success"`, with
`mode: "full" | "range" | "pending"`, `completed: true`, and `saved: true`.
Range results add canonical requested `start`/`end`, not measured change bounds.
Errors after analysis starts retain `mode`, `program`, requested bounds, and
`completed: false`; cancellation adds `cancelled: true`. The session boundary
reports whether partial changes were saved. A save failure retains the completed
command response under `command_response` with outer `saved: false` and
`save_failed: true`; completion and persistence are distinct.

`analysis_option_list` returns `{options, count}`;
`analysis_option_get` takes an exact string `name` and returns one option.
Each option has `name`, native `type`, `value`, `default`, `description`, and
`settable`; enums also have `choices` containing constant names. Numeric and
boolean values are JSON numbers/booleans; strings, file paths and enum constants
are strings. Other native types use Ghidra's string representation and are not
settable. Defaults/descriptions can be null for unregistered saved options.
`analysis_option_set` takes string `name` and string `value`, parses the value
using the existing option type, saves without analyzing, and returns the option
with `status: "set"`. Integers are decimal, floats must be finite, booleans are
true/false, enums must match a choice exactly, and file paths must be absolute
because the JVM's working directory can differ from the caller's. List queries
run in Rust; get/set output only supports projection and format controls.

`program_context_list` returns `{registers, count}` with processor-context
register rows `{name, bit_length}`, sorted by name. `program_context_get` takes
`register`, explicit `start`, and optional inclusive `end` (defaulting to start).
`program_context_set` and `program_context_clear` require both endpoints;
set also requires a nonnegative decimal or `0x` integer string `value` fitting
the register width. Endpoints select one ascending memory-space range; context
can describe unmapped addresses in that space.

Get/set/clear return `{register, bit_length, start, end, ranges}`. Each range has
inclusive `start`/`end` and `stored`, `default`, and `effective` objects, each
containing unsigned hexadecimal string `value` and `mask`. A zero mask means
unknown, including when value is `"0x0"`; effective values combine defaults with
recorded bits. Rows cover the entire requested range, including unknown gaps,
and coalesce only when all three representations match. Set/clear return the
post-edit ranges and add `status: "set" | "cleared"`. Clear unsets recorded bits,
including native decoding/analysis values; it is not an undo operation. Neither
edit clears instructions or starts analysis. Native conflicts fail through the
ordinary rollback boundary with the register, range, reason, and recovery hint.

`program_rebase` takes an explicit absolute `base` in the default address space.
It returns `old_base`, `new_base`, signed decimal string `delta_bytes`,
`moved_blocks`, and `unchanged_blocks`. Moved rows contain `name`, `old_start`,
`old_end`, `new_start`, and `new_end`; unchanged rows contain `name`, `start`,
`end`, and `reason` (`overlay`, `other_address_space`, or `same_base`). A same-base
request returns no moved blocks. Only default-space memory and its associated
Program addresses move. Block ranges cannot wrap; failed or cancelled rebases
roll back through the ordinary request boundary. Memory bytes are unchanged,
relocations are not reapplied, and analysis is not started.

`tag_get` accepts an exact, case-sensitive `name` and returns one tag object:
`{name, comment, use_count}`. `use_count` is Ghidra's total usage, including
external functions when present. Membership queries use `list_functions` with
`tags`, which lists non-external functions.

`tag_attach` and `tag_detach` take `function` and `tags`; detach also accepts
`all: true` instead of names. Both require existing definitions and validate
all names before editing. Results contain `attached`/`already_present` or
`detached`/`not_present` name arrays; they do not create or delete definitions.

`xref_create_memory`, `xref_delete`, and `xref_set_primary` take explicit `from`
and `to` addresses and integer `operand_index` (`-1` is the mnemonic reference).
Creation requires `ref_type` and uses `USER_DEFINED`. Delete/primary take
`source` (default `USER_DEFINED`) as an expected-origin check, not an additional
identity field. Receipts keep `before`/`after` nested: primary changes include
the operand's reference set and old primary origin. They are single results.

`equate_create` takes `name` and string `value`: signed 64-bit decimal or an
unsigned hexadecimal 64-bit pattern. `equate_list` returns `{equates, count}`;
`equate_get` and `equate_delete` take `name`. Definition values are hexadecimal
`value` and decimal `signed_value` strings. Get also returns `references` with
address, operand, dynamic hash and operand selectability. Enum-backed definitions
are distinguishable in reads and cannot be edited.
`equate_attach`/`equate_detach` take `name`, explicit `address`, and nonnegative
integer `operand_index`. Unknown names fail; known definitions with no selected
association detach successfully without change. Delete removes the ordinary
definition and every association, including dynamic uses.

`namespace_list` returns `{namespaces, count}`; `namespace_get` takes `path`.
`namespace_create` takes a component `name`, optional full `parent` path, and
`kind` (`namespace` by default, or `class`). Rows use string `id`, `name`, `path`,
nullable parent path, and `kind`. Paths are rooted at global scope without a
global-prefix component. `symbol_set_namespace` and `symbol_set_primary` take
`name` plus a single stable symbol snapshot in `targets`, using the same
revalidation as rename/delete. Namespace movement adds either `namespace`
or `global: true`; native function/type effects remain in the receipt.

`bookmark_set` takes `address`, `text`, `type` (default `Note`), and required
`category`; `bookmark_delete` takes the same identity without text. Identity
strings are case-sensitive, and an address need not be mapped. Set returns the
bookmark row with `status`; delete returns the identity and `deleted` count.

`symbol_externals`, `symbol_entry_points`, `tag_list`, `graph_calls`,
`graph_callers`, `graph_callees`, `find_instruction`, and `find_constant` accept `limit` only in
`0..=2147483647`. Graph `depth` uses the same checked range and defaults to 1.
Missing/null limits default to zero (unlimited); fractional, nonnumeric and
overflowing values fail. The CLI validates these limits before bridge work,
including when filtering leaves the limit in Rust. Other long-based paging
arguments retain their existing range.

`find_constant` takes either `value` or both `min` and `max` as decimal or
`0x`-prefixed integer strings. Nonnegative values compare unsigned; a negative
value or minimum selects signed comparison. A signed range's maximum must fit
signed 64-bit. Optional `bits` selects a Scalar width in 1..=64, while `start`
and `end` use the same inclusive instruction-address bounds as `find_instruction`.
Only Scalar objects in existing instruction operands are scanned. Results use
`{results, count}` with `address`, `disasm`, `operand_index` (zero-based), `bits`,
unsigned hexadecimal `value`, decimal `signed_value`, and `function` when known.
Both value representations are strings to preserve all 64 bits across consumers.

`type_field_set`, `type_field_clear`, and `type_field_delete` take `type_name`
and exactly one selector: struct `offset`, union `ordinal`, or exact existing
`field` name. `field_name` sets a new name; it never selects a target.
`type_field_clear` accepts structures only. Offset deletion requires a defined
field's exact start and rejects bit-fields and zero-length fields; named struct
deletion retains support for those components. Union offsets overlap, so ordinal
selection uses the zero-based value returned by `type_get`.

`type_field_append` and the three edits return a common receipt:
`{status, changed, name, path, kind, size_before, size_after, before, after}`.
`name`, `path`, and `kind` identify the containing type. Sizes describe that
type, with logical size zero for empty composites. `before` and `after` are
component snapshots using the `type_get.components` schema, or null when no
defined field exists on that side of the edit. Status is `appended`, `created`,
`updated`, `cleared`, `deleted`, or `unchanged`; `changed` is false only for
`unchanged`. Clearing already-undefined space returns two null snapshots.

`type_enum_member_delete` takes `type_name` and exact `member_name`; other enum
names with the same value are preserved.

`bookmark_list` and `bookmark_get` return `{bookmarks, count}` with `address`,
`type`, `category`, and `comment`. Get takes an explicit `address` and retains
all types/categories there, including external and unmapped addresses.
`program_list_relocations` returns `{relocations, count}`; rows retain native
`address`, numeric `type`, `status`, nullable `symbol_name`/`values`, and nullable
hex `original_bytes`. Multiple relocations at one address remain separate.
`function_list_calling_conventions` returns `{calling_conventions, count}` with
`name` and `is_default` from the selected Program's compiler specification.
These lists fetch complete inputs for the common Rust query pipeline.
`function_set_calling_convention` accepts only names in that selected compiler
specification's list; unsupported names fail before the function is changed.

`function_set_return_type` preserves uncommitted input parameters before fixing
the return type. Newly inferred parameter types remain undefined where this
preserves their ABI storage; types needed for their ABI placement are retained.
Existing explicit parameter metadata is preserved. `parameters_committed` counts
newly saved inferred parameters, or zero when none were added. Thunk edits report
the ultimate metadata owner as `effective_function` and `effective_address`.
Required decompilation or parameter preservation failures roll back the request;
an explicit complete `function_set_signature` is the recovery path when the
parameter definition cannot be inferred safely.

`function_var_list` takes `target` and returns
`{function, address, program, modification, variables}`. Rows describe the fresh
decompiler view: `name`, `type`, `type_path`, `size`, `storage`, `kind`, plus
parameter `ordinal` or local `first_use` (an absolute address or null).
`function_var_get/set` take `target` and exact `var_name`; set also takes
`new_name` and/or `type_name`. Get returns `{function, address, decompiler, database}`,
with a nullable matching saved definition. Set returns `status: "updated"`,
`function`, `address`, `kind`, the pre-edit `decompiler` row, and database
`before`/`after`; `before` can be null. Database rows add `source` and parameter
`auto_parameter`. These reads do not commit inferred variables.

CLI get/set filters select from `function_var_list`, then pass a `selection`
guard containing `program`, `function_address`, `modification`, and the complete
selected `variable` row. The bridge verifies the current program/function and
modification number, decompiles again, and requires the same unique row before
reading or mutating. Without a guard, the exact name must itself be unique.
No Rust filter is sent to Java; a filter is never applied to the edit receipt.

`function_set_body` takes `target` and nonempty `ranges: [{start, end}, ...]`.
The inclusive union replaces the complete selected body and retains its entry;
it never follows a thunk target. Receipts contain `function`, `address`,
`changed`, `before`/`after` with `body_ranges` and byte `size`, and `effects`:
`deleted_labels`, `deleted_references`, `disassociated_variable_references`.
Counts describe observed native changes. Reapplying the current union returns
`changed: false` and zero counts.

`function_call_signature_get/set/clear` take caller `target` and explicit `at`.
Set also takes `signature` and optional `convention`; omission chooses the Program
default and inline convention text is rejected. Every result identifies
`function`, caller-entry `address`, `call_site`, `in_body`, `instruction_exists`,
effective `call_count`, and nullable `call_kind` (`direct`/`indirect` for one call).
Get adds nullable `override`; set/clear add `changed`, `before`, `after`, and
`status: "call_signature_set"`/`"call_signature_cleared"`.
An override contains `return`, `params`, `variadic`, `calling_convention`, and
`no_return`. Return/parameter records include `type`, `type_path`, and byte `size`;
parameters also include `ordinal` and `name`.
Set requires an exact instruction start inside the caller with one effective
`CALL` or `CALLIND`; get/clear can address a saved override after that call or
body membership disappears. An absent override is null, and clearing it succeeds
unchanged. Neither operation resolves the caller to a thunk's final owner.

`listing_flow_get/set/clear` take explicit instruction `address`. Set accepts
`override` (`branch`, `call`, `call-return`, or `return`) and/or `fallthrough`,
or exclusive `no_fallthrough: true`. Clear takes boolean `override` and/or
`fallthrough` selectors. Omitted dimensions remain unchanged. Get returns
`address`, `instruction`, `raw_flow`, `effective_flow`, `override` (also `none`),
`fallthrough: {raw, default, effective, overridden}`, `delay_slot_depth`,
`in_delay_slot`, and `flow_references` with `to`, `type`, `operand`, `source`,
and `primary`. `raw` comes from the instruction prototype; `default` includes
flow override but excludes explicit fallthrough; `effective` includes both.
Set/clear return `{address, changed, before, after}` with those snapshots.
These edits and body/call-signature edits use the ordinary atomic save boundary
and do not start full analysis.

`memory_info` takes a name-or-address `address` and returns one object with the
resolved `address` and `kind`: `instruction`, `data`, `undefined`, or `unmapped`.
Nullable `instruction`/`data` describe the containing top-level code unit with
`address`, inclusive `end`, byte `size`, and byte `offset` from its start;
instruction adds `mnemonic`, data adds `type`/`type_path`. Nullable `function`
has its name/entry address; nullable `memory` has block name, permissions,
inclusive bounds, and `initialized`. Undefined listing state and uninitialized
memory are independent. `initialized` is the native block flag; byte/bit-mapped
blocks report false even when their backing bytes are readable. This query does
not decode data values. `file_mapping.state` is `mapped`, `unmapped`, or
`unsupported`. A mapped location includes `filename`, original `file_offset`,
relative `file_bytes_offset`, and provenance shared with `memory_file_mappings`;
other states include a reason.

`read_memory` accepts `source: "memory" | "original"` (default `memory`) and
echoes the selected source with `address`, `size`, and `hex`. Current-memory
reads retain pointer candidates. Original reads require preserved FileBytes
for the complete requested range and return source `mappings` instead of pointer
candidates. Each mapping includes its address/end/size and file provenance.
Indirect bit/byte mappings are explicitly unsupported; host files are not read.

`memory_file_mappings` accepts optional `file_offset` (a nonnegative decimal or
`0x` integer string) and `source_at` (an explicit address with a direct FileBytes
mapping). It returns `{mappings, count, unsupported_mappings}`. Each row has
`address`, inclusive `end`, byte `size`, `block_start`, and mapped-file provenance.
Without `file_offset` a row covers one direct source interval; with it each match
is a one-byte interval. `file_offset` is relative to the original file;
`file_bytes_offset` is relative to its preserved FileBytes region. `source_at`
identifies the first direct address of that FileBytes under native address order;
`source_file_offset` and `source_size` describe its preserved original-file span.
These fields also appear in `memory_info.file_mapping` and original-read mappings.
Anchors are recalculated per request, and equal filenames never merge FileBytes.
Unloaded portions have no rows. `unsupported_mappings` contains excluded
address/end/block_start/reason records, including when `source_at` is selected
because indirect mappings cannot be classified as direct matches. Rust retains
this context and supplied selectors in `meta`, and applies normal query paging.

`memory_block_create` takes `name`, explicit `start`, byte `size`, `permissions`
(`r`/`w`/`x` combinations or `none`), and exactly `uninitialized: true` or integer
`fill` (0..255). Optional `volatile` defaults false; optional `overlay` names a new
space over the physical start space. An existing overlay is selected in `start`.
`memory_block_rename`, `memory_block_set_permissions`,
`memory_block_set_volatile`, `memory_block_move`, and `memory_block_delete` take
an exact explicit `block_start`; their new values are `name`, `permissions`,
boolean `value`, or explicit `start`, respectively. Move stays in the same space;
nonloaded overlays, such as overlays of `OTHER`, cannot be moved.
Block edits return `{status, changed, before, after}` with nullable descriptions;
delete also reports `overlay_removed`. Descriptions include name, bounds, byte
size, permissions, initialized/loaded flags, address space, overlay/base space,
native block type, and volatility. Map retains `is_initialized`; info and receipts
use `initialized`. Mapped blocks cannot be edited, and move/delete cannot affect
indirect-mapping backing ranges. These are ordinary atomic requests with no
automatic reanalysis; move/delete use Ghidra's native analysis-update semantics.

`data_list` takes `limit` and returns `{items, count}` for top-level defined
data; filtering, sorting and offset remain in Rust. `data_read` takes `target`,
`max_depth` (default 2), and `max_elements` (default 100). It returns the selected
typed object with parent metadata for interior targets. Expanded components
share one element budget; zero means no expansion, not unlimited. Scalar
`state` distinguishes available/unavailable values; aggregates contain
`components`. Integers are decimal strings with bit width and signedness;
pointer values retain address-space identity. `truncated` propagates to the root
and local `truncation_reasons` explain omitted content.

`function_set_stack_purge` takes `target` and either integer `bytes` or
`unknown: true`. Function queries and edit receipts use
`stack_purge: {state: "known" | "unknown" | "invalid", bytes: integer | null}`.
The edit receipt returns the resulting value and identifies a thunk's effective
metadata owner when different from the requested function.

`program_export` retains `status`, `format`, and `output`, and adds
`program_path`, `requested_scope: "program"`, actual `artifacts` with path/size,
`exporter_messages`, and format-specific `limitations`. Requested scope is not
a claim of complete exported coverage; XML includes its `.bytes` companion.

Function detail (`get_function`) includes inclusive `body_ranges` without
adding them to function lists. Optional `with_signature: true` adds
`signature_details: {storage_mode, source, variadic, return, params}` from the
current Program's Function API, without decompilation. Storage mode is `dynamic`
or `custom`; source is the native signature SourceType, not a confidence rating.
Return/parameter records have effective `type`, `type_path`, byte `size`, native
display-string `storage`, and `forced_indirect`. Indirect records also have
`formal_type` and `formal_type_path`. Parameters include zero-based `ordinal`,
`name`, and nullable `auto_parameter` (native AutoParameterType name), in signature
order including auto-parameters. Native `<VOID>`, `<UNASSIGNED>`, and `<BAD>`
storage remain distinct. Dynamic storage and auto-parameters are computed from
the Program definition and compiler specification, not decompiler inference.
Custom storage does not retain auto-parameter classification. A thunk's details
include `thunk_function`/`thunk_address` for its immediate target and
`effective_function`/`effective_address` for its ultimate metadata owner;
the parameter view still comes from the selected function so native
thunk-specific `this` types are retained. Without the flag the field is omitted.
`function_set_signature` also identifies a thunk's ultimate owner with top-level
`effective_function` and `effective_address`.

Independent `with_frame: true` adds `frame_details` from the saved Function and
StackFrame APIs. It contains `frame_size`, `local_size`, `parameter_size`,
nullable `parameter_offset`, `return_address_offset`, `grows_negative`, and
`stack_variables`. Sizes and offsets are bytes; local size can include the ABI's
reserved prefix. `effective_function`/`effective_address` always identify the
actual frame owner, including thunk forwarding. Stack variable rows contain
`name`, `kind`, `type`, `type_path`, `size`, full `storage`, `stack_offset`,
`stack_size`, and `source`; parameters add `ordinal`/`auto_parameter`, locals add
`first_use_offset`. This is saved layout, not runtime stack consumption or purge.

Xref rows include native `operand_index`,
`source`, and `primary`; operand `-1` is the mnemonic reference. Incoming
deduplication includes the operand so distinct references stay selectable.
`program_info` adds nullable `executable_md5` and `executable_sha256` from
imported-file metadata, not from current memory bytes.
Its `language_id` and `compiler_spec_id` are exact import-compatible IDs;
`language` remains a display description and `compiler` is executable metadata.

Type components include zero-based `ordinal` and `is_bitfield`. Bitfields expose
effective `bit_size`, `bit_offset` within the component storage, and
`base_type`/`base_type_path`; these four fields are null for ordinary components.
The byte `offset`/`size` describe Ghidra's minimal component storage, so a bit
offset is not relative to the entire base type or structure.

`type_get` includes nullable `universal_id` and `source_archive` with `id`,
`name`, and `kind`. IDs are strings, preserving their precision; source metadata
does not describe an open archive connection. Struct and union sizes report
logical zero for empty definitions.

Function-definition types additionally include `return`, ordered `params`,
`calling_convention`, `variadic`, `no_return`, and nullable `comment`.
Return/parameter records contain `type`, `type_path`, and byte `size`; parameters
also contain `ordinal`, `name`, and nullable `comment` from the saved definition.

`type_clone` takes `type_name`, `new_name`, and optional existing `category`;
`type_move` takes `type_name` and existing `category`. Clones get local identities
and share dependencies; moves retain identity. `type_category_list/create/delete`
take absolute `path`. List returns immediate `categories` rows with `name`,
`path`, and direct `type_count`, retaining the selected category path as context.
Create includes missing parents; delete requires an empty non-root category.

`type_resize` takes `type_name` and nonnegative byte `size` for a non-packed
structure. It preserves defined components and verifies size propagation before
the ordinary request commits. `type_field_create_bitfield` takes `type_name`,
`offset`, `storage_size`, `bit_offset`, `bit_size`, `field_type`, optional
`field_name`, and optional `comment`. Bit positions are relative to the specified
Program-endian integer. Creation and non-packed width/base-type edits reject
clipping and overlap. `type_field_set` accepts `bit_size`; bitfields are selected
by real `field` name or `ordinal`, never byte offset. Struct clear/delete also
accept ordinals. Non-packed bitfield deletion leaves later offsets unchanged.

Decompilation includes `basic_block_count` from HighFunction p-code blocks,
or null when that result is unavailable. `with_jump_tables: true` adds
`jump_tables: [{switch_address, cases: [{address, label, is_default}]}]`.
Case order and raw signed 32-bit Java labels retain the native API result;
they do not establish the source expression's signedness or original width.
`is_default` follows Ghidra's switch analyzer: the native `0xbad1abe1` label or
the first destination beyond the label array. Later missing labels stay null.
An empty array means no tables were returned; null means HighFunction is
unavailable. Without the flag, the field is omitted. Explicit C output remains
code-only.

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

## Persistence and recovery

`bridge_info.auto_save: true` advertises saving before successful program
responses. `program_save` retries pending saves without restarting. A save failure
returns `error` with `detail.save_failed: true`, `saved: false`, and the original
`command_response`; do not replay the edit. The first save failure in a request
is returned without an implicit retry, leaving pending edits for explicit save.

Ordinary failures roll back the request's Program changes and report
`detail.rolled_back: true`; cancellation adds `detail.cancelled: true`.
Earlier requests and pending unsaved edits remain intact. The
[non-atomic exceptions and transaction ownership rules](../ghidra/scripts/ghidracli/README.md#execution-and-ownership)
are owned by `ProgramSession`. Non-atomic errors report
`detail.partial_changes_saved: true` when retained Program changes were saved;
external project/file effects are outside rollback.

Ownership failures report `detail.transaction_failed: true`, without claiming
rollback or saving. A leaked child transaction leaves rollback pending;
`command_response` is retained for diagnosis. Keep the bridge running and close
the outstanding transaction through its owning script; recovery scripts remain
available. Never replay the edit or save while rollback is pending.

`bridge_info.atomic_edits: true` advertises this request rollback contract. The CLI
requires it alongside `auto_save` and `explicit_addresses` before program dispatch;
a missing capability fails with explicit bridge-restart guidance, without sending
the program command or automatically upgrading the bridge. Explicit `program_save`
uses the direct recovery path and remains available before restarting an older
bridge with pending edits.

## Other command distinctions

`xrefs_from` reads references from the exact resolved `address`. With `function: true`,
it resolves the containing function and reads its full body, including disjoint ranges.
`string_refs` takes `pattern`, a case-insensitive substring of defined string values.
It includes references to any byte within each matching definition. Rows retain
`string_address` and `string_value`, while `to` is the actual destination and
`string_offset` is its byte displacement from the string start, not a character index.
`comment_delete` requires exactly one of `comment_type` (EOL/PRE/POST/PLATE,
case-insensitive) or `all: true`. Invalid or missing scope fails before deletion.

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

## Addresses and symbol targets

`bridge_info.explicit_addresses: true` advertises this address contract.
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
