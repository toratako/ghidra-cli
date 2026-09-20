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

The explicit non-atomic exceptions are `analyze`, `script_run`, `import`,
`program_export`, `open_program`, `program_close`, `program_save`, and
`program_delete`. Their analysis, arbitrary script, project, or filesystem effects
can outlive failure or cancellation. Retained Program changes are saved through
the session boundary and reported as `partial_changes_saved` on errors when saved;
external effects are not rolled back. A batch has one boundary per request, never
one transaction covering every command.

Atomic failures report `detail.rolled_back: true`, plus `cancelled: true` when
applicable. `ProgramTransaction` retains its Program and verifies ownership:
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
| `ProgramCommands`, `ProgramSession` | Program metadata, import/export/analysis, selection and release |
| `ImportSupport` | Name/loader selection and saving of detached imported programs; shared with bootstrap |
| `ProjectDeletion` | Bootstrap-only project removal under Ghidra's project lock |
| `FunctionCommands`, `FunctionSignatureCommands`, `DecompileCommands` | Function CRUD, signature/variable changes, decompilation |
| `TypeCommands`, `TypeImportCommands`, `TypeResolver`, `StructureFields` | Data types, C parsing/import, type-name resolution, validated offset edits |
| `TagCommands`, `TagSupport`, `SymbolCommands`, `CommentCommands` | Program annotations and symbols |
| `ListingCommands`, `SearchCommands`, `XrefCommands` | Listings, searches, references |
| `ListQuery` | Literal contains, checked page bounds and matching-row offset/limit for the five supported list handlers and defined-string search; see [query execution](../../../query/README.md) |
| `StringQueries` | Shared defined-string scan and row generation for list/search; pattern and query filter precede paging; `char_length` counts Unicode code points and `byte_length` is the data definition's occupied bytes |
| `GraphCommands`, `DiffCommands`, `PcodeCommands` | Graph traversal, comparisons, p-code |
| `MemoryCommands`, `AnalysisCommands` | Memory/disassembly operations, analyzer configuration |
| `ScriptCommands`, `ArtifactManifest` | Script compilation/execution and output-artifact validation |
| `AddressCodec`, `AddressResolver`, `FunctionQueries`, `NameSuggestions` | Explicit address syntax/formatting, shared lookup and diagnostics; no handler-to-handler dependencies |
| `CallReferences` | Shared incoming call-site validation and thunk/typed-pointer traversal for search and caller graphs |

Handlers construct domain results; the dispatcher adds the wire envelope.
Errors use `error` for messages and `detail` for diagnostics. Additional fields
(e.g. script `stdout`/`artifacts`) merge into wire `detail`, whose existing fields
take precedence. Shared helpers own lookup/serialization, not routing. Only
`BridgeRuntime` and `ScriptAccess` cross the default-package entry point boundary;
most classes are package-private.

`AddressCodec` owns strict parsing and address serialization. Numeric colon
components require `0x`/`0X`, with optional address-space qualification. Segmented
output always includes the space name and preserves both components, for example
`ram:0x1234:0x0005`; a registered numeric-looking space name takes precedence
when parsing an unqualified-looking input. Word addresses preserve `.byte` remainders.
Use `format(Address)` for address fields and generated diagnostics, and
`parse(AddressFactory, String)` for address-only inputs. `isExplicit` classifies
explicit-looking input, including malformed tokens; `isValidSyntax` validates
syntax when no program factory exists, such as import base-address options.
`AddressResolver` looks up unprefixed input as exact names, never bare-hex or
`FUN_...` address inference. Do not pass user address text directly to Ghidra's
permissive factory parser. Instruction/decompiler text, byte strings, numeric
offsets, and user-script stdout keep their native representation.

`StructureFields` stages offset edits on a detached structure copy, validates
field boundaries and conflicts, then applies only the target component edit in a
request-owned transaction. Never replace the whole structure with the staged copy:
Ghidra discards component settings when rebuilding it. Metadata-only edits update
the original component, preserving its settings; layout edits leave other
components' settings intact.
`set-field`, `clear-field`, and explicit-offset `add-field` share this path;
append and `del-field` retain their existing behavior. Never use packed
replacement/clearing for offset edits: Ghidra may repack or delete components.
Metadata-only edits preserve packing. Zero-length structures report a logical
size of 0 here despite Ghidra's minimum display length of 1.

Memory write validation rejects empty, odd-length, or invalid hex before clearing code
units or changing block permissions. Callers supply verified bytes through
`memory_write`. Export success
requires completed file writes and a true Ghidra exporter result; exporter logs
are included when it returns false. File outputs are outside Program transactions.
`ProgramCommands` references `Exporter` directly so OSGi imports the exporter
package even though concrete exporter names are selected dynamically.
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

`ImportSupport` owns the loader's detached programs until save/release. Bootstrap
analysis uses an owned `ProgramTransaction` and ends it before saving. Bridge
imports do not analyze detached programs: the caller opens the saved file and
uses the usual session analysis/save boundary. Do not rename an already saved
input-name file to implement `--program`; supply the name to the importer.

`analyze` is the sole explicit analysis command; `analyzer_list` and
`analyzer_set` only inspect or change settings. Ghidra's `analyzeAll()` initializes
options and schedules full reanalysis itself, so callers must not separately
call `reAnalyzeAll(null)`. The CLI retains its `command/status/data` response
with the saved program name and function count.

`ProgramSession.analyzeAll()` and detached import analysis check cancellation
before recording Ghidra's standard analyzed flag. The ordinary request/import
save boundary persists that record. Program lists read the live option for the
selected file and saved metadata for other files; missing or malformed flags are
`null`, never inferred from function counts. `ProgramSession.programFiles()` owns
the recursive file enumeration shared by program lists and control snapshots.

`find_calls_to` resolves a target across the selected program, follows thunk and
typed pointer references, and emits only call sites. `function_calls` retains the
outgoing scan of one function. Distinct wire names cause an older bridge to report
an unknown command instead of silently returning results for the wrong direction.

`find_instruction` scans existing listing instructions using literal text matching
(`Locale.ROOT` when case-insensitive). It and `disasm_range` share inclusive,
same-address-space bounds in `AddressResolver.instructionRange`; one-sided search
bounds stay in the supplied address space. Both check cancellation during iteration
and have no hidden scan cap. The client sends an uncapped fetch when filtering,
sorting, counting, or offsetting needs all rows. `disasm_range` has a distinct wire
name so an older bridge cannot silently ignore `disassemble --end`.

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
hits. Integration tests cover normal cross-buffer and contiguous-block matches,
memory gaps, unsigned bytes, zero-length errors, query limits and cancellation.

`disasm` reads existing instructions from the resolved start, retaining its
containing-instruction/function-entry fallback. It uses checked
nonnegative-long `limit` bounds, with missing/null/zero meaning unlimited, and
checks cancellation while collecting instructions. The CLI applies its configured
default.

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
the whole body. Rust fetch planning applies the
usual query limits and requests all rows before client-side selection when needed.

## Validation

`bridge/sources.rs` tests source inventory/publication; `daemon_tests` exercises
runtime loading, control responsiveness, cancellation isolation, program switching,
request rollback after late failures/cancellation, save recovery, foreign
transaction rejection, and edits surviving failed requests and restart.
See [test commands](../../../../tests/README.md).
