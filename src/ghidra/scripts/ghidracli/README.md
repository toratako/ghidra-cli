# Java bridge

`../GhidraCliBridge.java` adapts inherited state/operations to `ScriptAccess` and
calls `BridgeRuntime` on the original script thread. The short-lived
`../GhidraCliBootstrap.java` handles durable import and diagnostic project creation.
Both share the source bundle, with no separate Java build, JAR installation, or
per-handler script instance.

## Execution and ownership

```text
GhidraCliBridge -> BridgeRuntime
                    |-- BridgeServer: socket, client pool, response pool
                    |      `-- JobScheduler.handleRequest
                    |             |-- control request: immediate response
                    |             `-- program request: bounded FIFO
                    `-- JobScheduler.runProgramJobs (original script thread)
                              `-- CommandDispatcher -> command handler
                                                           `-- ProgramSession
                                                                  `-- ScriptAccess
```

`BridgeServer` owns networking and request/shutdown callbacks. `JobScheduler`
owns the FIFO (256 jobs), history (100 jobs), cancellation, and status snapshots.
Completed history retains metadata only, releasing response futures/payloads.
Per-job cancellation must not cancel the parent script monitor or later jobs.
Queued cancellation removes jobs immediately; active jobs cancel cooperatively
via per-job monitors. Connection handlers enqueue without waiting on program
futures; completed futures use a separate bounded response pool. Neither waiting
clients nor socket writes may block controls or the program thread. Shutdown
rejects new program jobs and drains accepted work, keeping controls available.
`shutdown_wait` completes only after the program thread saves and releases the
session. On save failure it returns structured error detail and restores request
acceptance with the same session/listener. Only successful completion closes the
listener and returns to Ghidra. Shutdown signaling must remain responsive when
the queue is full; control handlers must not block while trying to append a shutdown
sentinel.

`ProgramSession` owns request transactions, saving, switching, and release; it
reads the current Program, GhidraState, and monitor from the script. Handlers/helpers
retain the session, never a cached Program/monitor. `JobScheduler` installs a
fresh `JobTaskMonitor` per request and restores the script monitor in `finally`.
Controls read snapshots/job records instead of the session. Switching resolves
the project file before checking whether it is open: different files can have
Programs with the same internal name.

CLI program names and paths come from `ProgramSession.programName()` and
`programPath()`, which read the selected DomainFile. Use these for responses,
artifact manifests, and the snapshots published by the program thread. Ghidra's
internal Program name is not the project file identity and must not be renamed
just to change CLI output.
`programFiles()` filters by the DomainFile's domain-object class so program lists
and status counts exclude archives while recognizing linked Programs.

The entry script calls its inherited `end(true)` before serving requests to end
the transaction created by `GhidraScript.executeNormal()`. Never end an unknown
transaction ID or leave the script's transaction ID tied to a switched program.
`CommandDispatcher` wraps every program request, including analysis/scripts, in
a `ProgramSession` request boundary. Ordinary requests are atomic by default,
including future commands: failure, cancellation, or a native transaction abort
rolls back the whole request. Successful requests end their transaction and save
before replying. Earlier requests remain intact; unchanged databases are not
written. Ordinary handlers never start/end transactions or save. They report
native false returns and cancellation as failures so the shared boundary can
roll back compound edits such as clearing before redisassembly.

The explicit non-atomic exceptions are `analysis_run`, `script_run`, `import`,
`program_export`, `open_program`, `program_close`, `program_save`, and
`program_delete`. Their analysis, arbitrary script, project, or filesystem effects
can outlive failure or cancellation. Retained Program changes are saved through
the session boundary and reported as `partial_changes_saved` on errors when saved;
external effects are not rolled back. A batch has one boundary per request, never
one transaction covering every command.

Atomic failures report `detail.rolled_back: true`, plus `cancelled: true` when
applicable. Rolled-back errors include the selected DomainFile path as `program`,
captured on the program lane so recovery cannot select a different program from
a later control snapshot. `ProgramTransaction` retains its Program and verifies ownership:
an ordinary request cannot start inside a pre-existing foreign transaction; that
transaction and its edits remain untouched. If native code leaves a child open
inside the known atomic root, end only the owned root entry with `commit: false`
to mark it aborted. Rollback completes when the remaining entries are closed by
their owners; the failed request's edits cannot subsequently be committed.
Until cleanup completes, report `transaction_failed` without `rolled_back` and
do not save. Recovery scripts remain available. Never end an unknown transaction ID.

Bounded code definition uses `ProgramSession.preview()` before any mutations in
the atomic request. Preview verifies the sole owned transaction and unchanged
Program modification number, ends that untouched transaction without committing,
runs a program-only preview in a separate transaction that is always rolled back,
then restores the request transaction after completed rollback. A leaked preview
child instead fails the request through the same pending-rollback ownership path.
Preview must not switch programs or return live listing objects invalidated by
rollback; return detached values. A preview
after an edit is rejected so earlier edits in the same request cannot be committed
as a side effect of preview setup.

Saving uses a non-cancelled monitor after commit. Atomic rollback does not save
pending edits retained from an earlier save failure. Save errors fail the response,
retain `command_response` with `save_failed: true`, and keep the program available
for in-place `program_save` retries. The first save failure in a request is retained
without an implicit retry during request completion.
Switching/closing save before releasing the session's consumer; failed save/open
keeps the previous program. Shutdown drains, saves, and releases on the script
thread. Startup omits `-process`, so `ProgramSession` also owns the initial program.
Opening initializes the analyzer options previously registered by HeadlessAnalyzer.
Deletion rejects non-Program files with the same class check as program listings,
before changing selection or deleting anything. It closes the selected Program
before removing it; a refused deletion restores the selection. Never release
another consumer or terminate its checkout.

## Command boundaries

| Classes | Responsibility |
|---|---|
| `CommandDispatcher`, `JsonProtocol` | Explicit command table, arguments, success/error envelopes |
| `ProgramCommands`, `ProgramSession` | Program metadata, import/analysis, selection and release |
| `ProgramContextCommands` | Processor-context registers, interval values/masks, and context edits |
| `ProgramRebaseCommands` | Image-base preflight and block movement receipts |
| `ProgramExportCommands` | Native exporters, artifact receipts, and GZF publication |
| `ImportSupport` | Name/loader selection and saving of detached imported programs; shared with bootstrap |
| `ProjectDeletion` | Bootstrap-only project removal under Ghidra's project lock |
| `FunctionCommands`, `FunctionSignatureCommands`, `DecompileCommands` | Function CRUD, signature/variable changes, decompilation |
| `FunctionReturnType` | Preserve uncommitted parameters before return edits lock a signature; validate compiler-specific calling convention names |
| `DecompilerSession` | Session-owned native decompiler reuse, invalidation and shutdown |
| `DecompileWarnings` | API diagnostics and warning-comment extraction from C markup, preserving provenance |
| `MemoryBlockInfo` | Block name and permission serialization shared by memory and function queries |
| `MemoryInfoCommands`, `MemorySources` | Listing classification and preserved FileBytes provenance/reads |
| `DataCommands` | Applied data values, interior component selection and bounded expansion |
| `TypeCommands`, `TypeImportCommands`, `TypeResolver`, `TypeFields`, `StructureFields`, `UnionFields` | Data types, C parsing/import, type-name resolution, validated struct/union edits |
| `TagCommands`, `TagSupport`, `SymbolCommands`, `CommentCommands`, `BookmarkCommands` | Program annotations and symbols |
| `NamespaceCommands`, `NamespaceSupport` | Root-relative namespace lookup, creation, and shared identity serialization |
| `EquateCommands` | Exact named constants, operand associations, and native dynamic-reference preservation |
| `ListingCommands`, `SearchCommands`, `XrefCommands` | Listings, searches, references |
| `ConstantSearch` | Signed/unsigned value matching over existing instruction Scalar operands |
| `ListQuery` | Literal contains, checked page bounds and matching-row offset/limit for the five supported list handlers and defined-string search; see [query execution](../../../query/README.md) |
| `StringQueries` | Shared defined-string scan and row generation for list/search; pattern and query filter precede paging; `char_length` counts Unicode code points and `byte_length` is the data definition's occupied bytes |
| `GraphCommands`, `DiffCommands`, `PcodeCommands` | Graph traversal, comparisons, p-code |
| `MemoryCommands`, `MemoryPatch` | Memory/disassembly operations and preservation checks for byte edits |
| `AnalysisCommands` | Full/range/pending analysis dispatch and typed analyzer configuration |
| `ScriptCommands`, `ArtifactManifest` | Script compilation/execution and output-artifact validation |
| `AddressCodec`, `AddressResolver`, `FunctionQueries`, `NameSuggestions` | Explicit address syntax/formatting, shared lookup and diagnostics; no handler-to-handler dependencies |
| `CallReferences` | Shared call-site validation, endpoint resolution, and incoming/outgoing enumeration for all call graphs |

Handlers construct domain results; the dispatcher adds the wire envelope.
Errors use `error` for messages and `detail` for diagnostics. Additional fields
(e.g. script `stdout`/`artifacts`) merge into wire `detail`, whose existing fields
take precedence. Shared helpers own lookup/serialization, not routing. Only
`BridgeRuntime` and `ScriptAccess` cross the default-package entry point boundary;
most classes are package-private.

`FunctionReturnType` decompiles internal `DEFAULT` signatures before a return edit
can lock an empty or partial input declaration. Rebuilding retains existing
parameter metadata and stores new inferred types as sized undefined types only
when the calling convention assigns the same parameter storage. Keep required
floating-point/aggregate types instead of switching to custom storage just to
relax their types. Parameter conflicts fail the request without force-removing
locals or renaming symbols; the GUI's commit helper permits both side effects.
Existing explicit declarations, external functions, and undefined return types
do not require decompilation; undefined return types do not raise signature source.

`AddressCodec` owns strict parsing and address serialization. The
[wire address contract](../../../ipc/README.md#addresses-and-symbol-targets) covers space qualification, numeric-looking space names, and word remainders.
Use `format(Address)` for address fields and generated diagnostics, and
`parse(AddressFactory, String)` for address-only inputs. `isExplicit` classifies
explicit-looking input, including malformed tokens; `isValidSyntax` validates
syntax when no program factory exists, such as import base-address options.
`AddressResolver` owns exact-name lookup. Do not pass user address text directly
to Ghidra's permissive factory parser. Instruction/decompiler text, byte strings,
numeric offsets, and user-script stdout keep their native representation.

`StructureFields` stages offset edits on a detached structure copy, validates
field boundaries and conflicts, then applies only the target component edit in a
request-owned transaction. Never replace the whole structure with the staged copy:
Ghidra discards component settings when rebuilding it. Metadata-only edits update
the original component, preserving its settings; layout edits leave other
components' settings intact.
`TypeFields` resolves mutually exclusive selectors and builds the common field
receipt. Names match actual field names, never generated display names. Named
struct set/clear resolve to the guarded offset path; named deletion can identify
bit-fields and zero-length components that offset deletion must reject.
`field set` and `field clear` share the staged edit path. `field append` appends
using native packing/alignment; `field delete` removes components and allows
native compaction. Both `field append` and `field set` validate explicit
sizes before applying changes; `field set --size` requires `--type`.
Never use packed replacement/clearing for offset edits: Ghidra may repack or
delete components.
Metadata-only edits preserve packing. Zero-length structures report a logical
size of 0 here despite Ghidra's minimum display length of 1.

Memory write validation rejects empty, odd-length, or invalid hex before mutation.
`MemoryPatch` validates the initialized range and plans against only changed bytes.
It retains data records/settings, clears overlapping instructions using Ghidra's
delay-slot boundaries, and writes separate changed ranges so unchanged instructions
never reach `Memory.setBytes`. Block permission flags describe the target program;
database byte edits do not require toggling them.

Preflight walks affected data components, evaluates built-in string storage lengths
against a bounded patched buffer with the original settings, and rejects unknown
dynamic layouts. All overlapping union members must remain valid, but none is
selected for pointer updates. Pointer values use the applied type's interpretation;
only matching DEFAULT DATA references on operand 0, including pointer-typedef
component offsets, are replaced. Other references retain their source, form, and
primary status and suppress automatic additions on that operand. Never call
`updateDataReferences`, which removes explicit references. Changes through mapped
blocks or their mapped source ranges are rejected until all affected views can be
validated together. The shared request boundary rolls back write/reference failures
and cancellation; this helper owns no transactions or saves.

`MemorySources` resolves direct FileBytes sources, adding the FileBytes origin
only for original-file provenance; reads use the relative FileBytes offset.
It rejects indirect bit/byte mappings instead of assuming a 1:1 correspondence.
Original reads must map the complete requested range and never consult host files.

`DataCommands` reads through applied `Data` instances so component settings and
bitfield layouts stay native. Interior lookup stops at overlapping components;
unions expose alternative members. Depth and a shared element budget bound
expansion, while scalar/string materialization has a byte cap. Unreadable values
remain unavailable and exact integers are serialized as decimal strings.

Export success
requires completed file writes and a true Ghidra exporter result; exporter logs
are included when it returns false. File outputs are outside Program transactions.
`ProgramExportCommands` references `Exporter` directly so OSGi imports the exporter
package even though concrete exporter names are selected dynamically.
Success receipts include actual artifact sizes (including XML's sidecar), native
exporter messages and format limitations, without inferring complete coverage.
GZF packing first ends the non-atomic request transaction and saves through
`ProgramSession.save()`. It writes to private sibling staging and
atomically replaces the destination after successful packing and a cancellation
check; never let GzfExporter delete the user's previous destination directly.

`TypeResolver` uses fixed-width primitives for fallback stdint/short aliases;
ordinary C aliases remain ABI-dependent. Validate type sizes, field definitions,
and enum members before mutation, especially before force-clearing existing data.
Function lookup rejects ambiguous names with candidates instead of selecting the
first match. Artifact hashing failures propagate as validation errors. Artifact
minimum row counts use the shared checked nonnegative-long argument parser and
are validated before script execution, including for direct bridge requests.
Type deletion resolves registered program types directly; detached array/pointer
expressions are not database identities. Alias fallback must match a registered
type before resolving its stored path; a matching path alone can name an unrelated
user type. Rename success requires the actual name
to match the request, since immutable Ghidra types can ignore `setName()`.

Function signatures use `FunctionSignatureParser` with a missing space inserted
between a pointer return declarator and its function name. Explicit C type
qualifiers are rejected before parsing because Ghidra function datatypes cannot
retain them; switching to `CParser` would silently discard some qualifiers.
Persistence and qualifier rejection are covered in `tests/types/signatures.rs`.

`FunctionQueries.functionContext` supplies `is_external` and `entry_memory` to
function get/list, decompilation results, and native decompilation failure details.
The block summary describes only the entry address; no block yields JSON null.
The function-list iterator still selects Ghidra's memory functions.

Completed decompilation includes a `warnings` array. Each item has `source`
(`decompiler` for the API message or `c_comment`), `message`, and a nullable
`address`. `DecompileWarnings` inspects comment markup, including its spacing and
line breaks, rather than scanning C strings for warning text. Markup does not
preserve whether a comment was engine-generated or user-written; keep that
distinction explicit through provenance. The generated C is unchanged. Native
failures, cancellation, and timeout retain their existing failure paths.

Union edits select existing members by ordinal, since their byte offsets overlap.
`UnionFields` validates additions and replacements on detached copies. Type
replacement applies the final union in one `replaceWith` call: a live delete then
insert would notify parent types of an intermediate size and can damage their
layouts. Preserve explicit component settings across replacement, retaining only
supported settings on the changed member. Metadata-only edits modify the member
directly. The shared request transaction owns rollback and persistence.

Symbol name lookups retain Ghidra's indexed results and supplement them with
matching displayed names from the symbol-list iterator, deduplicating by symbol
ID. The iterator includes default thunks and dynamic labels that the name index
can omit, but excludes namespaces and variables, so it cannot replace the index.
Preserve cancellation and complete ambiguity/snapshot checks for mutations.
Multi-symbol deletion rolls back all deletions when any member fails. Failure
detail uses `attempted_deleted`, `failed`, and `not_attempted`; reserve `deleted`
and `count` for successful receipts so rolled-back attempts are not reported as
committed deletions.
Comment listing scans all comment addresses, including external and unmapped
addresses, while retaining the four supported comment types and query ordering.

Tag attach/detach validates every requested definition before changing any
membership. Attach never creates a definition; detach keeps unused definitions.
Bookmark mutations identify one exact address/type/category and retain other
bookmarks at that address, including analysis diagnostics.

Namespace mutations reuse stable symbol snapshots for one selected label or
function. Class moves retain Ghidra's native type/parameter effects and report
the before/after function state. They never infer a new calling convention.
Symbol primary selection cannot replace the function symbol at its entry point.

Xref mutations select `(from, to, operand_index)` and compare `source` before
deletion or primary changes. Creation refuses native replacement of conflicting
references, including non-memory references on the operand. Offset/shift,
fallthrough, and p-code override references are not editable through the
ordinary-memory contract. Native insertion translates unmapped overlay
destinations into physical addresses; reject that case instead of changing the
requested destination.

Equate values are stored as native 64-bit values and emitted as strings. Operand
attachment compares the Scalar's native signedness/width without truncation.
Ghidra's instruction-wide dynamic hashes can replace other operand references;
preflight and post-edit checks preserve unrelated associations. Operand-only
detach must not select ambiguous or dynamic-only references. Definition deletion
intentionally removes every use of that ordinary Equate; enum-backed definitions
remain read-only. All these edits use the ordinary request transaction/save boundary.

Keep the reflective OSGi loading in `ScriptCommands`: it avoids introducing
imports of Ghidra-internal packages that the source bundle cannot resolve. A
successful plain `javac` invocation does not validate this class-loader boundary.
File and stdin Java sources share JDK declaration parsing for their qualified
class name. Keep the source's immediate parent as its explicitly selected bundle;
derive package names from the parser, not directory names or regex matching.
File declarations are parsed after the bundle build to preserve compile diagnostics.

Decompiler parameters use `LocalSymbolMap.getParamSymbol(i)` order; `getSymbols()`
is hash-ordered. All native decompiler callers share checked `timeout_secs` with
zero as unlimited and a 2,147,483-second ceiling to avoid Ghidra's millisecond
conversion overflow. High p-code and variable edits use the same CLI budget as
ordinary decompilation.

`ProgramSession` owns one lazy `DecompilerSession`, shared by decompilation,
high p-code and variable edits on the program thread. Each call reads the current
Program and request monitor. Reuse requires the same Program object and modification
number; any change, including saved edits or rollback, causes reopening on next use.
Results are not retained. Ghidra flushes native function/symbol data after each
decompilation; reopening also refreshes language and address-space initialization.
Failure or cancellation closes the interface. Switching/closing saves first,
then synchronously closes the decompiler before releasing the Program;
`dispose()` alone defers cleanup to Ghidra's disposer thread. A failed save retains
the live session.

`ImportSupport` owns the loader's detached programs until save/release. Bootstrap
analysis uses an owned `ProgramTransaction` and ends it before saving. Bridge
imports do not analyze detached programs: the caller opens the saved file and
uses the usual session analysis/save boundary. Do not rename an already saved
input-name file to implement `--name`; supply the name to the importer.

`ProgramSession.analyzeAll()` explicitly initializes saved analyzer options for
all supported Ghidra versions. The native `analyzeAll()` entry point schedules
full reanalysis; `analysis_run` must not separately call `reAnalyzeAll(null)`.
Range analysis intersects the requested inclusive range with memory before
`reAnalyzeAll`; never pass an empty set, which Ghidra interprets as full analysis.
`ProgramSession.analyzeRange()` and `analyzePending()` initialize saved options
and drain work through `analyzeChanges()`. Range analysis seeds work and can
process existing pending work or follow references beyond the requested bounds.
Pending mode drains the current queue without scheduling full reanalysis.
The queue is not durable; native cancellation, Program close, and restart discard
pending work. Analysis remains a non-atomic request: completion, cancellation,
and partial-change persistence are reported separately.

`AnalysisCommands` reads `Program.ANALYSIS_PROPERTIES`, preserving native types,
defaults and descriptions. Validate before `putObject`; unknown names must not
create options. Setting options never schedules analysis. See the
[wire contract](../../../ipc/README.md) for value representation and
`tests/daemon/analysis.rs` for independent saved-database and persistence checks.

`ProgramSession.analyzeAll()` and detached import analysis check cancellation
before recording Ghidra's standard analyzed flag. The ordinary request/import
save boundary persists that record. Range and pending analysis do not set it.
Program lists read the live option for the selected file and saved metadata for
other files; missing or malformed flags are
`null`, never inferred from function counts. `ProgramSession.programFiles()` owns
the recursive file enumeration shared by program lists and control snapshots.

`ProgramContextCommands` limits register selection to processor context and
keeps stored, default, and effective values separate. Interval output covers
unknown gaps and coalesces only when all value/mask pairs match. Overlay queries
translate default-value lookup to the physical space. Set/clear alter recorded
context only; native instruction conflicts must fail with recovery detail,
never trigger implicit clearing or analysis. Clear removes current stored bits,
including values established by native decoding, rather than restoring a prior
user value. The ordinary session boundary owns rollback and saving.

`ProgramRebaseCommands` preflights each default-space block's endpoints with
`BigInteger` byte offsets and the actual space minimum/maximum before native
`setImageBase`. Reject wraparound instead of using native wrapping arithmetic.
`validateMetadata()` also checks the interval that would wrap for symbols
(except stationary pinned labels), reference endpoints, comments, stored
base-register context, bookmarks, public user property maps, relocations,
equate references, and function bodies. Language context defaults are excluded;
listing definitions and source-map entries are covered by their mapped blocks.
The public metadata checks do not inspect script-created Program
`AddressSetPropertyMap` or `IntRangeMap` tables.
Overlays and other spaces remain unchanged and appear in the receipt. Native
image-base movement has no task monitor; cancellation checks before and after it
allow the ordinary request boundary to roll back a cancelled edit. The handler
does not rewrite bytes, reapply relocations, run analysis, or own transactions.

`CallReferences` owns call validation and thunk/typed-pointer resolution for
`graph_callers`, `graph_callees`, and `graph_calls`. Incoming traversal follows
reverse references to function bodies (including interior destinations), thunks,
and typed pointer slots; every candidate is checked by the same outgoing edge
resolver. One call site can have multiple destinations; duplicate references to
one resolved landing address produce one row, preferring CALL evidence over READ/DATA.
Distinct landing addresses within one function remain distinct calls. Typed pointer
resolution precedes containing-function lookup so embedded literal pools are not
misidentified as callees.
Undefined endpoint metadata is null, and known destination addresses are retained.
Outgoing root selection inspects the selected function body without canonicalizing
it to a thunk's target. Resolved callees are canonicalized for subsequent traversal.
`GraphCommands` uses BFS with one expansion per function and preserves call edges
at every level, including cycles and endpoints without a function. A missing
function stops expansion, not row emission. Depth defaults to one level; row depth
starts at zero, and a zero depth/limit argument is unlimited. Limits count rows
for traversal queries and source function nodes for the whole-program graph.

`find_instruction` scans existing listing instructions using literal text matching
(`Locale.ROOT` when case-insensitive). It and `disasm_range` share inclusive,
same-address-space bounds in `AddressResolver.instructionRange`; one-sided search
bounds stay in the supplied address space. Both check cancellation during
iteration and have no hidden scan cap; see
[query planning](../../../query/README.md) for fetch limits.

`find_bytes_regex` uses Ghidra's `RegExByteMatcher` and `MemorySearcher` over
loaded, initialized memory. `SearchCommands` resolves those optional classes
through Ghidra's application class loader on demand, so installations without
the API can still compile/start the bridge and run other commands. Reflection
also tolerates the transition from non-generic to generic search classes.
Keep Java regex syntax errors from reflective calls readable. Native
`MemoryMatch` rejects zero-byte matches; surface this as an error, never silently
skip them. Check the session monitor before and after the native search and
while serializing hits: native cancellation can otherwise look like successful
partial results. Cancellation is cooperative and cannot interrupt an individual
Java regex evaluation. The native implementation uses finite buffers/overlap;
do not promise unbounded match spans, global anchor semantics, or all overlapping
hits.

`disasm` retains its containing-instruction/function-entry fallback when
resolving the start and checks cancellation while collecting instructions.

`define_code` returns a change receipt, never instruction
rows, and rejects query bounds such as `limit`. `target` and optional inclusive
`end` resolve as exact names or explicit addresses in the same space. Existing
instructions at the target are left unchanged. Auto-analysis is not run as part
of the definition operation. The native flow-following disassembler
retains custom processor decoding, future context, delay slots, and no-return
handling. For bounded calls, `definitionStarts` previews and rolls back the
native command, excludes starts whose complete instruction/delay-slot group
crosses the byte bounds, and repeats until safe before the real run. Ghidra's
plain restricted address set only bounds instruction starts, so it alone is not
sufficient. Never replace this with per-instruction decoding, which loses flow
context such as Thumb IT. `clear_range` keeps its optional redisassembly; clearing
and redisassembly share the atomic request. A failed redisassembly receipt has
`status: "failed"` and never claims that the clearing remains applied.

`function_disasm` resolves a function through `FunctionQueries` and reads existing
instructions from its complete `getBody()` address set, including disjoint ranges.
It shares instruction serialization with `disasm_range`; interior targets select
the whole body.

## Validation

`bridge/sources.rs` tests source inventory/publication; `daemon_tests` exercises
runtime loading, control responsiveness, cancellation isolation, program switching,
request rollback after late failures/cancellation, save recovery, foreign
transaction rejection, and edits surviving failed requests and restart.
See [test commands](../../../../tests/README.md).
