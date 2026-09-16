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
closes the listener, rejects new jobs, and drains accepted work before returning
to Ghidra. Shutdown signaling must remain responsive when the queue is full;
control handlers must not block while trying to append a shutdown sentinel.

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

The entry script calls its inherited `end(true)` before serving requests to end
the transaction created by `GhidraScript.executeNormal()`. Never end an unknown
transaction ID or leave the script's transaction ID tied to a switched program.
`CommandDispatcher` wraps every program request, including analysis/scripts, in
a `ProgramSession` transaction, ends it, and saves changes before replying.
Unchanged databases are not written; no mutating-command list is maintained.

Handler mutations must use `session.transaction()`. `ProgramTransaction` retains
its Program and nesting state: nested aborts would erase other changes in the
request, so nested handlers retain partial changes; standalone transactions honor
commit/rollback. Earlier requests are already committed and saved. Failed requests
flush retained changes and report `partial_changes_saved` in error detail.

Saving uses a non-cancelled monitor after the transaction ends, even on cancelled
requests. Save errors fail the response, retain the command response in error
detail, and keep the program available for in-place `program_save` retries.
Switching/closing save before releasing the session's consumer; failed save/open
keeps the previous program. Shutdown drains, saves, and releases on the script
thread. Startup omits `-process`, so `ProgramSession` also owns the initial program.
Opening initializes the analyzer options previously registered by HeadlessAnalyzer.
Deletion closes the selected file before removing it; a refused deletion restores
the selection. Never release another consumer or terminate its checkout.

## Command boundaries

| Classes | Responsibility |
|---|---|
| `CommandDispatcher`, `JsonProtocol` | Explicit command table, arguments, success/error envelopes |
| `ProgramCommands`, `ProgramSession` | Program metadata, import/export/analysis, selection and release |
| `ImportSupport` | Name/loader selection and saving of detached imported programs; shared with bootstrap |
| `FunctionCommands`, `FunctionSignatureCommands`, `DecompileCommands` | Function CRUD, signature/variable changes, decompilation |
| `TypeCommands`, `TypeImportCommands`, `TypeResolver`, `StructureFields` | Data types, C parsing/import, type-name resolution, validated offset edits |
| `TagCommands`, `TagSupport`, `SymbolCommands`, `CommentCommands` | Program annotations and symbols |
| `ListingCommands`, `SearchCommands`, `XrefCommands` | Listings, searches, references |
| `GraphCommands`, `DiffCommands`, `PcodeCommands` | Graph traversal, comparisons, p-code |
| `MemoryCommands`, `AnalysisCommands` | Memory/patch/disassembly operations, analyzer configuration |
| `ScriptCommands`, `ArtifactManifest` | Script compilation/execution and output-artifact validation |
| `AddressResolver`, `FunctionQueries`, `NameSuggestions` | Shared lookup and diagnostic logic; no handler-to-handler dependencies |

Handlers construct domain results; the dispatcher adds the wire envelope.
Errors use `error` for messages and `detail` for diagnostics. Additional fields
(e.g. script `stdout`/`artifacts`) merge into wire `detail`, whose existing fields
take precedence. Shared helpers own lookup/serialization, not routing. Only
`BridgeRuntime` and `ScriptAccess` cross the default-package entry point boundary;
most classes are package-private.

`StructureFields` stages offset edits on a detached structure copy, validates
field boundaries and conflicts, then applies the result in a session transaction.
`set-field`, `clear-field`, and explicit-offset `add-field` share this path;
append and `del-field` retain their existing behavior. Never use packed
replacement/clearing for offset edits: Ghidra may repack or delete components.
Metadata-only edits preserve packing. Zero-length structures report a logical
size of 0 here despite Ghidra's minimum display length of 1.

Patch validation rejects empty, odd-length, or invalid hex before clearing code
units or changing block permissions. NOP patching supports only x86; other
processors must supply verified bytes through `patch_bytes`. Export success
requires completed file writes and a true Ghidra exporter result; exporter logs
are included when it returns false. File outputs are outside Program transactions.
GZF packing first ends the request transaction and saves through
`ProgramSession.preparePackedExport()`. It writes to private sibling staging and
atomically replaces the destination after successful packing and a cancellation
check; never let GzfExporter delete the user's previous destination directly.

`TypeResolver` uses fixed-width primitives for fallback stdint/short aliases;
ordinary C aliases remain ABI-dependent. Validate type sizes, field definitions,
and enum members before mutation, especially before force-clearing existing data.
Function lookup rejects ambiguous names with candidates instead of selecting the
first match. Artifact hashing failures propagate as validation errors.

Keep the reflective OSGi loading in `ScriptCommands`: it avoids introducing
imports of Ghidra-internal packages that the source bundle cannot resolve. A
successful plain `javac` invocation does not validate this class-loader boundary.

`ImportSupport` owns the loader's detached programs until save/release. Bootstrap
analysis uses an owned `ProgramTransaction` and ends it before saving. Bridge
imports do not analyze detached programs: the caller opens the saved file and
uses the usual session analysis/save boundary. Do not rename an already saved
input-name file to implement `--program`; supply the name to the importer.

`find_calls_to` resolves a target across the selected program, follows thunk and
typed pointer references, and emits only call sites. `function_calls` retains the
outgoing scan of one function. Distinct wire names cause an older bridge to report
an unknown command instead of silently returning results for the wrong direction.

## Validation

`bridge/sources.rs` tests source inventory/publication; `daemon_tests` exercises
runtime loading, control responsiveness, cancellation isolation, program switching,
and edits surviving failed mutations and restart. See [test commands](../../../../tests/README.md).
