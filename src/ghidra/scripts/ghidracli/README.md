# Java bridge

`../GhidraCliBridge.java` adapts inherited state/operations to `ScriptAccess` and
calls `BridgeRuntime` on the original script thread. It is the only GhidraScript
entry point; all classes share one source bundle, with no separate Java build,
JAR installation, or per-handler script instance.

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
Queued cancellation removes jobs immediately; active jobs cancel cooperatively
via per-job monitors. Connection handlers enqueue without waiting on program
futures; completed futures use a separate bounded response pool. Neither waiting
clients nor socket writes may block controls or the program thread. Shutdown
closes the listener, rejects new jobs, and drains accepted work before returning
to Ghidra.

`ProgramSession` owns request transactions, saving, switching, and release; it
reads the current Program, GhidraState, and monitor from the script. Handlers/helpers
retain the session, never a cached Program/monitor. `JobScheduler` installs a
fresh `JobTaskMonitor` per request and restores the script monitor in `finally`.
Controls read snapshots/job records instead of the session. Switching resolves
the project file before checking whether it is open: different files can have
Programs with the same internal name.

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
| `FunctionCommands`, `FunctionSignatureCommands`, `DecompileCommands` | Function CRUD, signature/variable changes, decompilation |
| `TypeCommands`, `TypeImportCommands`, `TypeResolver` | Data types, C parsing/import, type-name resolution |
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

Patch validation rejects empty, odd-length, or invalid hex before clearing code
units or changing block permissions. NOP patching supports only x86; other
processors must supply verified bytes through `patch_bytes`. Export success
requires completed file writes and a true Ghidra exporter result; exporter logs
are included when it returns false. File outputs are outside Program transactions.

Keep the reflective OSGi loading in `ScriptCommands`: it avoids introducing
imports of Ghidra-internal packages that the source bundle cannot resolve. A
successful plain `javac` invocation does not validate this class-loader boundary.

## Validation

`bridge/sources.rs` tests source inventory/publication; `daemon_tests` exercises
runtime loading, control responsiveness, cancellation isolation, program switching,
and edits surviving failed mutations and restart. See [test commands](../../../../tests/README.md).
