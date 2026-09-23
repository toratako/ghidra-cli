# Java bridge

`../GhidraCliBridge.java` adapts inherited state/operations to `ScriptAccess` and
calls `BridgeRuntime` on the original script thread. The short-lived
`../GhidraCliBootstrap.java` handles durable import, project maintenance, and
diagnostic project creation.
Both share the source bundle, with no separate Java build, JAR installation, or
per-handler script instance.

## Packages and dependencies

Directories match Java packages. Register each source at that same relative path
in [the embedded inventory](../../bridge/sources.rs); startup and doctor use one
complete source tree. Its unit tests check source coverage, package paths, and
acyclic imports between bridge packages.

| Package | Ownership |
|---|---|
| [runtime](runtime/) | Bridge startup, sockets, job scheduling, command construction and dispatch |
| [session](session/) | Live script state, Program selection, transactions, saving, and native decompiler lifetime |
| [protocol](protocol/) | JSON arguments, error diagnostics, and response envelopes |
| [query](query/) | Shared address/numeric parsing, target resolution, paging, and name suggestions |
| [project](project/) | Durable import, project archives, and project deletion, also used by bootstrap |
| [program](program/) | Program metadata, processor context, rebase, and export commands |
| [function](function/) | Function queries/edits, signatures, variables, and function tags |
| [types](types/) | Type resolution/definitions and composite field layouts |
| [memory](memory/) | Byte reads/patches, blocks, original file bytes, and mappings |
| [listing](listing/) | Instruction/data/string listings, searches, code/data definition, and flow edits |
| [symbol](symbol/) | Symbols, namespaces, references, equates, comments, and bookmarks |
| [analysis](analysis/) | Analysis execution, decompilation, p-code, CFG, and call graphs |
| [script](script/) | User script execution and artifact validation |

`runtime` constructs handlers, which depend on `session`, never on `runtime`.
`session` depends only on `protocol` within the bridge. `query` uses the live
session for lookup/cancellation and does not depend on feature packages.
Shared domain helpers stay with their domain: `FunctionQueries` in `function`,
`TypeResolver` in `types`, and `MemoryBlockInfo` in `memory`.

Function disassembly resolves the function in `function` and reads instruction
rows through `listing.InstructionListing`. `listing` and `memory` do not depend
on `function`. Function tags belong to `function`; symbol and analysis commands
can use function lookup without a reverse dependency. Handlers do not call other
handlers; shared bit-field editing lives in `types.BitFields`.

Public classes/methods are the entry points used by another package or a headless
entry script. Keep domain-only helpers and methods package-private. The native
decompiler stays with its owner in `session`, independently of which feature
requests decompilation.

## Project archives

`ProjectArchive` owns one-shot GAR creation/restoration and Ghidra's target lock.
`GarFile` implements the standard `ArchiveTask`/`RestoreTask` layout: `JAR_FORMAT`,
a `.gpr` marker, and `.rep` subdirectory contents at the ZIP root. It excludes
root project properties/state and database locks. A private copy is opened for
project validation and link inspection, never the source. Repository identity
is read without connecting to the server; external resources are not followed.
Filesystem links at or inside `.rep` are rejected: linking only the database
directory does not alias Ghidra's sibling project lock. Use the real project base
path; aliases of the containing directory still work.
Link API reflection preserves compilation on older Ghidra versions and reports
incomplete inspection instead of asserting an absence of dependencies.

Archive publication uses a sibling hard link for atomic no-clobber creation;
filesystems without hard links fail. Restore validates entry names, namespace
collisions and CRCs before publication. It exclusively creates `.rep`, moves the
validated children into that owned directory, then exclusively creates `.gpr`.
The pair is not atomic; normal failures remove only owned incomplete artifacts.
Abrupt process termination can leave a partial `.rep`, which subsequent attempts
refuse. Cleanup failures report remaining paths and whether publication finished.

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
owns the FIFO (256 jobs), history (1,000 jobs), cancellation, and status snapshots.
Program requests supply a UUID before submission; duplicate retained IDs are
rejected before enqueueing. `JobResultStore` retains immutable UTF-8 JSON snapshots
after transaction/save completion and before response delivery. It limits each
body to 16 MiB, total bodies to 64 MiB, and availability to 30 minutes; capacity
evicts oldest bodies. Metadata preserves the unavailable reason until history
eviction. History never retains request arguments, futures, or live JSON objects.
Encoding occurs outside the scheduler lock (except the small fixed queued-cancel
receipt). Status, completion, and snapshot publication share that lock; result
decoding occurs after releasing it. An in-flight reader may finish from its
immutable snapshot after eviction. Expiry is applied on controls and completion.
Per-job cancellation must not cancel the parent script monitor or later jobs.
Queued cancellation removes jobs immediately; active jobs cancel cooperatively
via per-job monitors. Connection handlers enqueue without waiting on program
futures; completed futures use a separate bounded response pool. Neither waiting
clients nor socket writes may block controls or the program thread. `BridgeReply`
keeps small controls on connection threads and always sends program completions
and `job_result` work through the bounded response pool, even when already ready.
Shutdown
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
Each queued job retains its optional request-level program selector. The session
resolves and selects it on the original script thread before beginning the request
transaction, so no other client can switch programs between selection and dispatch.
If selection fails, `CommandDispatcher` runs neither the handler nor
`finishRequest`; a failed save of the previous program is not retried implicitly.
After execution, `JobScheduler` attaches the final selected DomainFile path or
explicit null as `selected_program` before retaining or delivering the response.
Admission failures and queued cancellations have no selection receipt; controls
never accept selectors or read the live session for one.

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
`program_export`, `type_export_gdt`, `open_program`, `program_close`, `program_save`, and
`program_delete`. Their analysis, arbitrary script, project, or filesystem effects
can outlive failure or cancellation. Retained Program changes are saved through
the session boundary and reported as `partial_changes_saved` on errors when saved;
external effects are not rolled back. A batch has one boundary per request, never
one transaction covering every command.

`type_archive_list` reads an external file on the same script lane without a
Program request boundary. It neither selects nor saves the current Program.
GDT export flushes the Program through `ProgramSession` before the handler runs;
a save failure therefore cannot publish an archive.

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
| [`CommandDispatcher`](runtime/CommandDispatcher.java), [`JsonProtocol`](protocol/JsonProtocol.java) | Explicit command table, arguments, success/error envelopes |
| [`ProgramCommands`](program/ProgramCommands.java), [`ProgramSession`](session/ProgramSession.java) | Program metadata, import/analysis, selection and release |
| [`ProgramContextCommands`](program/ProgramContextCommands.java) | Processor-context registers, interval values/masks, and context edits |
| [`ProgramRebaseCommands`](program/ProgramRebaseCommands.java) | Image-base preflight and block movement receipts |
| [`ProgramExportCommands`](program/ProgramExportCommands.java) | Native exporters, artifact receipts, and GZF publication |
| [`ImportSupport`](project/ImportSupport.java) | Name/loader selection and saving of detached imported programs; shared with bootstrap |
| [`ProjectDeletion`](project/ProjectDeletion.java) | Bootstrap-only project removal under Ghidra's project lock |
| [`FunctionCommands`](function/FunctionCommands.java), [`FunctionSignatureCommands`](function/FunctionSignatureCommands.java), [`DecompileCommands`](analysis/DecompileCommands.java) | Function CRUD, whole-function signature changes, decompilation |
| [`FunctionBodyCommands`](function/FunctionBodyCommands.java) | Whole-body union validation and observed native annotation/reference effects |
| [`FunctionThunkCommands`](function/FunctionThunkCommands.java) | Direct thunk relation updates and before/after signature ownership and ABI snapshots |
| [`FunctionCallSignatureCommands`](function/FunctionCallSignatureCommands.java), [`FunctionSignatureSupport`](function/FunctionSignatureSupport.java) | Exact caller/site prototype overrides and shared signature parsing |
| [`FunctionVariableCommands`](function/FunctionVariableCommands.java), [`FunctionVariables`](function/FunctionVariables.java) | Shared decompiler variable discovery/selection, saved definitions, and variable edits |
| [`StructureInferenceCommands`](analysis/StructureInferenceCommands.java) | Detached native structure recovery and bounded recorded LOAD/STORE evidence |
| [`FunctionReturnType`](function/FunctionReturnType.java) | Preserve uncommitted parameters before return edits lock a signature; validate compiler-specific calling convention names |
| [`DecompilerSession`](session/DecompilerSession.java) | Session-owned native decompiler reuse, invalidation and shutdown |
| [`InstructionCfg`](analysis/InstructionCfg.java) | Native instruction blocks, intrafunction edges, calls and body boundaries |
| [`HighPcodeModel`](analysis/HighPcodeModel.java), [`HighPcodeOutput`](analysis/HighPcodeOutput.java) | Request-local High IR identities and bounded serialization of their relationships |
| [`AnalysisContext`](analysis/AnalysisContext.java), [`AnalysisLimits`](analysis/AnalysisLimits.java) | Analysis provenance, result identity and shared output limits |
| [`DecompileWarnings`](analysis/DecompileWarnings.java) | API diagnostics and warning-comment extraction from C markup, preserving provenance |
| [`MemoryBlockInfo`](memory/MemoryBlockInfo.java) | Small block summaries for function queries and full descriptions for memory queries/receipts |
| [`MemoryBlockCommands`](memory/MemoryBlockCommands.java) | Exact-start block creation/attribute changes and native movement/deletion |
| [`MemoryInfoCommands`](memory/MemoryInfoCommands.java), [`MemorySources`](memory/MemorySources.java), [`FileMappingCommands`](memory/FileMappingCommands.java) | Memory map, listing classification, preserved FileBytes provenance/reads, and direct mapping interval/reverse queries |
| [`DataCommands`](listing/DataCommands.java) | Whole-object incoming reference counts, applied data values, interior component selection and bounded expansion |
| [`TypeCommands`](types/TypeCommands.java), [`TypeImportCommands`](types/TypeImportCommands.java), [`TypeResolver`](types/TypeResolver.java), [`TypeFields`](types/TypeFields.java), [`StructureFields`](types/StructureFields.java), [`UnionFields`](types/UnionFields.java) | Data types, C parsing/import, type-name resolution, validated struct/union edits |
| [`TypeArchiveCommands`](types/TypeArchiveCommands.java), [`TypeArchiveGraph`](types/TypeArchiveGraph.java) | GDT snapshots/publication, guarded root selection, dependency and ABI/identity validation |
| [`TypeDefinitionCommands`](types/TypeDefinitionCommands.java), [`TypeResizeCommands`](types/TypeResizeCommands.java), [`BitFieldCommands`](types/BitFieldCommands.java), [`BitFields`](types/BitFields.java) | Definition identity/settings, category operations, guarded size propagation, and shared explicit bitfield layouts |
| [`TypeUsesCommands`](types/TypeUsesCommands.java), [`TypeUseMatcher`](types/TypeUseMatcher.java) | Registered type identity, declaration wrapper paths, and applied-data/function-signature uses |
| [`SemanticTypeUsesCommands`](analysis/SemanticTypeUsesCommands.java), [`FieldUses`](analysis/FieldUses.java), [`TypeFieldTarget`](types/TypeFieldTarget.java) | Decompiler variable searches, native field access evidence, and unambiguous read-only component selection |
| [`TagCommands`](function/TagCommands.java), [`TagSupport`](function/TagSupport.java), [`SymbolCommands`](symbol/SymbolCommands.java), [`CommentCommands`](symbol/CommentCommands.java), [`BookmarkCommands`](symbol/BookmarkCommands.java) | Program annotations and symbols |
| [`NamespaceCommands`](symbol/NamespaceCommands.java), [`NamespaceSupport`](symbol/NamespaceSupport.java) | Root-relative namespace lookup, creation, and shared identity serialization |
| [`EquateCommands`](symbol/EquateCommands.java) | Exact named constants, operand associations, and native dynamic-reference preservation |
| [`ListingCommands`](listing/ListingCommands.java), [`InstructionListing`](listing/InstructionListing.java), [`SearchCommands`](listing/SearchCommands.java), [`XrefCommands`](symbol/XrefCommands.java) | Instruction/string listings, code definition/clearing, shared instruction rows, searches, references |
| [`ListingFlowCommands`](listing/ListingFlowCommands.java), [`InstructionFlow`](listing/InstructionFlow.java) | Flow/fallthrough edits and shared raw/effective instruction flow evidence |
| [`ConstantSearch`](listing/ConstantSearch.java) | Signed/unsigned value matching over existing instruction Scalar operands |
| [`ListQuery`](query/ListQuery.java) | Literal contains, checked page bounds and matching-row offset/limit for the five supported list handlers and defined-string search; see [query execution](../../../query/README.md) |
| [`StringQueries`](listing/StringQueries.java) | Shared defined-string scan and row generation for list/search; pattern and query filter precede paging; `char_length` counts Unicode code points and `byte_length` is the data definition's occupied bytes |
| [`GraphCommands`](analysis/GraphCommands.java), [`PcodeCommands`](analysis/PcodeCommands.java) | Graph traversal and p-code |
| [`MemoryCommands`](memory/MemoryCommands.java), [`MemoryPatch`](memory/MemoryPatch.java) | Current/original byte reads and preservation checks for byte edits |
| [`AnalysisCommands`](analysis/AnalysisCommands.java) | Full/range/pending analysis dispatch and typed analyzer configuration |
| [`ScriptCommands`](script/ScriptCommands.java), [`ArtifactManifest`](script/ArtifactManifest.java) | Script compilation/execution and output-artifact validation |
| [`AddressCodec`](query/AddressCodec.java), [`AddressResolver`](query/AddressResolver.java), [`IntegerLiteral`](query/IntegerLiteral.java), [`FunctionQueries`](function/FunctionQueries.java), [`NameSuggestions`](query/NameSuggestions.java) | Explicit address syntax/formatting, integer spelling, shared lookup and diagnostics; no handler-to-handler dependencies |
| [`CallReferences`](analysis/CallReferences.java) | Shared call-site validation, endpoint resolution, and incoming/outgoing enumeration for all call graphs |

Handlers construct domain results; the dispatcher adds the wire envelope.
Errors use `error` for messages and `detail` for diagnostics. Additional fields
(e.g. script `stdout`/`artifacts`) merge into wire `detail`, whose existing fields
take precedence. Shared helpers own lookup/serialization, not routing.
The default-package bridge entry script uses `runtime.BridgeRuntime` and
`session.ScriptAccess`; bootstrap uses the public import/archive/deletion
operations in `project`.

`function_set_thunk` and `function_clear_thunk` edit the selected function's
direct relation; they never follow it to the signature owner before writing.
Native thunk validation rejects cycles and cross-program destinations. Clear
removes only the relation, exposing the source's saved definition without
copying parameters, convention, or storage from the destination. Edit snapshots
read parameters through the selected function to retain native class-specific
`this` types, and identify both the direct target and final signature owner.

`data list` adds `incoming_reference_count` by iterating recorded reference
destinations within each top-level Data's inclusive address range and summing
their native counts into a Java `long`. Address spaces remain distinct. The
count includes self-references and separate operands, and does not scan object
bytes or expand components. `data read` does not perform this aggregation.

`TypeImportCommands` parses detached definitions in a temporary data-type manager
with the Program's data organization. It assigns destination categories to new
definitions and their anonymous dependencies before resolving into the Program.
References to existing types retain their source identity; explicitly declared
types resolve within the requested category instead of replacing a same-named root.

`TypeArchiveCommands` copies GDT input to a unique private path, hashes the copy,
and checks it against the source before reading and before completion. Opening
the original path is insufficient: Ghidra's packed-database cache can retain an
old archive when a replacement preserves its modification time. Read-only
snapshots also keep Ghidra's lock/cache side effects away from the source directory.
The immutable reader opens an uncached native `PackedDatabase` handle so closing
also removes its unpacked database. The regular file-manager factory caches even
unique temporary paths and can leave orphaned cache directories in a long-lived
JVM; no process-wide cache setting is changed.

`TypeArchiveGraph` collects roots and dependencies through defined components,
without expanding sparse undefined filler. It preflights both paths and source
IDs, resolves roots together with one conflict policy, and checks the resulting
graph, native layout, signedness, calling conventions, settings and FILE identities.
Ghidra equivalence alone omits some ABI/layout differences and uses a recursive
cache during resolve; conflict callbacks must not use it as an independent check.
Equivalent local definitions can adopt the incoming FILE identity. Different FILE
identities at one path, or one identity at different paths, are conflicts.

Export creates a new archive with the Program's architecture in a private sibling
directory. Program-local definitions acquire new file identities; existing FILE
origins are retained without editing the Program. Save/close/reopen validation
precedes atomic no-clobber hard-link publication. Unsupported hard-link filesystems
fail; cleanup removes only owned staging paths and reports any published output
and remaining paths. GDT cannot store component settings; unsupported settings
must not silently disappear in an otherwise successful export.

`TypeResizeCommands` follows native size propagation through composite, array,
and typedef parents and scans their applied Listing data. Before committing it
checks complete component lengths, native component counts, preserved definitions,
and explicit settings on applied components. Packed parent movement and array
stride changes are allowed only when existing settings keep their association.
The scan checks cancellation through defined fields and array elements; it does
not expand implicit struct filler. Applied zero-length roots are rejected because
Listing cannot represent their requested logical length. All failures use the
ordinary request rollback boundary.

`TypeUsesCommands` selects a registered Program type through `TypeResolver`, then
matches manager-qualified local type IDs while following only typedef, pointer,
and array wrappers. It reads top-level Listing data and function symbols in address
order; the null symbol address set includes unmapped and external functions that
`FunctionManager.getFunctions(boolean)` would miss. One row represents one data
definition, return, or parameter. Signature `type`/`type_path` and `wrappers` describe
the formal type; forced-indirect declarations also include `effective_type` and
`effective_type_path`. Automatic parameters and thunk signature owners retain
their native metadata. This request does not decompile or register types.
`scan.complete` describes exhaustion of the selected declaration iterators,
independently of subsequent Rust filtering and pagination. Cancellation fails the
request instead of returning a successful partial scan.

`SemanticTypeUsesCommands` uses the same matcher for fresh decompiler symbols.
Temporary pointer/array wrappers are compared down to registered leaf identity;
same-name or layout-equivalent composites never substitute for that identity.
The handler resolves function scope before scanning and uses the existing
session decompiler sequentially. It counts unmapped internal function bodies as
attempted work; external functions have no body to inspect. The `analysis`
package owns this orchestration so `types` does not depend on `function`.

`FieldUses` examines native C markup and the complete High P-code model, never
the capped serialized output. Field tokens supply their registered containing
type and native component identity; direct partial HighSymbols supply storage
offsets. Pointer def/use establishes memory reads and writes; address-taking
does not imply a callee's effects. Union and bitfield storage overlap alone
cannot establish a component identity. Newer native bitfield tokens are accessed
reflectively to keep older supported Ghidra installations loadable.
See [query execution](../../../query/README.md) for search completeness and limits.

`FunctionReturnType` decompiles internal `DEFAULT` signatures before a return edit
can lock an empty or partial input declaration. Rebuilding retains existing
parameter metadata and stores new inferred types as sized undefined types only
when the calling convention assigns the same parameter storage. Keep required
floating-point/aggregate types instead of switching to custom storage just to
relax their types. Parameter conflicts fail the request without force-removing
locals or renaming symbols; the GUI's commit helper permits both side effects.
Existing explicit declarations, external functions, and undefined return types
do not require decompilation; undefined return types do not raise signature source.

`FunctionVariables` supplies the same decompiler symbol population for list,
get, set, and structure inference. Name matching and optional selection guards
must resolve one fresh row; guards include program identity, function entry,
modification number, and the complete row. Check them again on the program lane
before any mutation.
Database snapshots remain separate from decompiler inference. A rename retains
an existing saved type; a newly saved inferred local uses sized undefined storage
instead of locking the inferred type. If an inferred parameter lacks a matching
saved slot, the native helper can commit all inferred input parameters with
their types and storage. Reject unsupported automatic parameter
edits without implicitly switching ABI storage to custom.

`StructureInferenceCommands` requires one whole HighVariable for the selected
symbol; `HighSymbol.getHighVariable()` alone can silently select the largest
partial variable. Eligibility follows the native GUI's pointer-size bound without
requiring a pointer type. It calls `FillOutStructureHelper.processStructure` with
new-structure enabled, class creation disabled, and no recursive decompiler.
Serialize only defined candidate components through `StructureFields.describe`;
the detached structure has no public registered name or path. The native size is
an inferred layout size, not a proven allocation bound. Native null with size zero
is an empty result; unrepresentable sizes fail. Keep helper-recorded LOAD/STORE
evidence separate from its conflict-resolved layout. `accesses_status` counts
recorded evidence, not all accesses; its limit affects output only.
Reject an unexpected Program modification so the ordinary request boundary rolls
it back. Poll cancellation before and after native recovery and during root and
output traversal; the helper itself does not poll throughout intrafunction work.

`FunctionBodyCommands` validates mapped, same-space range unions, entry retention,
other-function overlap, and complete instruction boundaries before `setBody`.
It operates on the requested function, including a thunk's own body. Native body
shrink removes direct local labels and stack/register references and can detach
variable associations. Receipts compare actual pre/post state; do not substitute
predicted counts. Nested namespaces, including call-site override markers, remain
independent of body membership.

`FunctionCallSignatureCommands` stores a prototype only at the selected caller's
site. Set validates exactly one effective `CALL`/`CALLIND` from `InstructionFlow`,
including flow overrides. Get/clear deliberately do not require current body
membership or a current call. Remove only that owner/site marker and run native
unused-override cleanup, preserving types shared by other sites. An unreadable
saved marker is a get error with clear guidance, not an absent override.

`ListingFlowCommands` preflights both requested dimensions before mutating.
Flow override requires a raw branch/call/return; explicit fallthrough requires an
instruction start in the same address space. Read raw flow from the prototype,
default fallthrough from the override-aware native default, and effective flow
and fallthrough from the current instruction. Native edits can change references;
return actual before/after snapshots. Ghidra cannot retain explicit no-fallthrough
on some instructions whose raw prototype has none, even if a flow override adds
a default successor. Check the resulting state and reject an unrepresentable
request atomically rather than report a suppression that did not persist.
A representable explicit null fallthrough changes Listing metadata but can leave
decompiled control flow unchanged: `InstructionPcodeOverride` exposes only
nonnull fallthrough destinations. Keep native metadata assertions separate from
decompiler effects; explicit target redirection and clearing are tested in both.
These handlers use `ProgramSession`'s ordinary transaction/save boundary and do
not invoke whole-program analysis.

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
Each request builds its own interval snapshot and FileBytes-identity anchor index;
never retain these across edits or program changes. `FileMappingCommands` lists
whole source intervals, or one-byte intersections for an original-file offset.
Excluded mappings remain response context even when there are no matches.

`MemoryBlockCommands` resolves explicit addresses and requires equality with the
block start before editing. Creation uses `Program.createOverlaySpace` for an
explicit new overlay name, then creates the block inside that exact space.
Movement stays in one space and uses `Memory.moveBlock`; deletion uses
`Memory.removeBlock`, including native analysis effects and last-overlay removal.
Both reject indirect-mapping backing intersections, including the move destination.
Check cancellation after the native calls, which may return after partial work;
`ProgramSession` owns rollback and saving. No handler reruns analysis or repairs
embedded pointer bytes. Ghidra's outside incoming references can retain the old
target, and deleting part of a function body can remove the entire function.

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

`FunctionSignatureSupport` uses `FunctionSignatureParser` with a missing space inserted
between a pointer return declarator and its function name. Explicit C type
qualifiers are rejected before parsing because Ghidra function datatypes cannot
retain them; switching to `CParser` would silently discard some qualifiers.
Call-site signatures choose calling convention through a separate validated
argument, defaulting to the Program convention; they discard the declaration's
function name without renaming or resolving a callee.
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
conversion overflow. High p-code and variable reads/edits use the same CLI budget as
ordinary decompilation.

`ProgramSession` owns one lazy `DecompilerSession`, shared by decompilation,
high p-code and variable reads/edits on the program thread. Each call reads the current
Program and request monitor. Reuse requires the same Program object and modification
number; any change, including saved edits or rollback, causes reopening on next use.
Results are not retained. Ghidra flushes native function/symbol data after each
decompilation; reopening also refreshes language and address-space initialization.
Failure or cancellation closes the interface. Switching/closing saves first,
then synchronously closes the decompiler before releasing the Program;
`dispose()` alone defers cleanup to Ghidra's disposer thread. A failed save retains
the live session.

`InstructionCfg` retains the full native blocks intersecting the function body,
including delay slots, and records their body intersection separately. Calls and
body crossings are distinct from intrafunction edges. Resolve destinations from
reference addresses without invoking lazy block lookup with a dummy monitor.

High p-code indexes one decompilation by native object identity, then serializes
selected nodes and relationships. Sequence identity is separate from block order;
CFG connection indices retain phi-input meaning. Space operands and `INDIRECT`
operation references are not ordinary values. IDs and native objects never survive
the request. Both representations check the request monitor during traversal and
serialization; cancellation follows the ordinary failed-request rollback path.
Output limits bound serialized nodes and relationships, not native analysis cost.

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

`PointerValues` shares native pointer decoding and exact target metadata between
memory and VTable reads. Preserve the encoded value, decoded address, normalized
code entry, and direct/final thunk identities separately. Use Ghidra's pointer
and code-mode APIs, retaining overlays; do not resolve a containing function as
the pointer's target. Neither reader defines instructions or data.

`VtableCommands` and `VirtualCallersCommands` share `VtableReader` for a
caller-selected address point and count;
`VtableHeaders` owns the explicit Itanium/MSVC layouts. Absolute Itanium uses
native-width header fields. LLVM relative32 components are relative to the
address point (including nonzero slot indices), and RTTI goes through a
native-pointer proxy. MSVC uses signature-0 32-bit absolute references or
signature-1 64-bit image-relative references plus self-RVA consistency. These
are shallow reads; no table-length heuristic or class recovery runs. Expected
memory failures become field/slot evidence; cancellation and unexpected API
failures propagate. Root completeness counts slot reads separately from header
completeness. Shared session ownership and transactions remain unchanged.

`VirtualCallersCommands` matches the target's exact entry or a Ghidra thunk chain
against the selected absolute-pointer slots, preserving each matching slot.
`VirtualCallTrace` follows native High P-code definitions at machine indirect
calls, using same-instruction raw definitions when optimization removed a load.
Concrete different slots are excluded; unknown bases retain only type or offset
evidence. Static types never establish dynamic object identity. Phi merges,
INDIRECT side effects, unsupported expressions, and trace budgets retain
unresolved diagnostics. No memory snapshot or earlier STORE is assumed to give
an object's runtime vptr. Indirect jumps/tail calls are outside this call search.

`DecompileScan` is shared by semantic type searches and virtual callers. It owns
request-local enumeration, native failure/warning accounting, limits and scope;
the session owns the native decompiler. Each function finishes inspection before
a pushed result cap stops the next function. Refer to the query module for
coverage and empty-slot semantics. Neither helper retains native results across
requests or starts transactions, creates references, or applies types.

`AddressTableSearch` loads the native `AddressTable` detector through Ghidra's
application classloader without importing its private GUI package into the
bridge bundle. It follows the native GUI settings and skips the full returned
table/index extent before continuing. Bounds select candidate starts in loaded,
initialized memory, not an internal detector read boundary. Check cancellation
after native detection because the API can return a partial table on cancellation.
Do not infer an internal stop reason the API does not expose. Native 24-bit
padded layouts and 1-/2-byte pointers are outside this detector adapter's contract.

`FunctionCandidateSearch` visits reference destinations within loaded, initialized,
executable memory. It admits exact instruction starts outside all function bodies,
excluding delay slots and both ordinary and remote overridden fallthrough.
`InstructionFlow.isCallReference` checks saved CALL evidence against effective
p-code, including native override selection; ordinary EXTERNAL relocation
references retain their symbolic meaning for call graphs. Candidate search keeps
the literal destination instead of resolving pointers or canonicalizing thunks.
It counts distinct call sites and retains five sample references per destination.
No disassembly, analysis, or function creation runs during the search.

`CallReferences` owns thunk/typed-pointer resolution and uses shared call validation for
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
