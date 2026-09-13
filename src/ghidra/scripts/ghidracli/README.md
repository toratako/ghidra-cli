# Java bridge

`../GhidraCliBridge.java` is the only GhidraScript entry point. It adapts inherited
fields and GhidraScript operations to `ScriptAccess`, then calls `BridgeRuntime`
on the original script thread. All classes here belong to one source bundle;
there is no separate Java build, JAR installation, or per-handler script instance.

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

`BridgeServer` owns network resources and receives callbacks for request handling
and shutdown. `JobScheduler` owns the bounded FIFO (256 jobs), recent history
(100 jobs), cancellation, and published status snapshots. Queued cancellation
removes the job immediately; active cancellation uses its per-job monitor
cooperatively. It never waits for socket writes on the program thread. Shutdown closes the listener, rejects new program jobs, and drains
accepted jobs before returning to Ghidra. Connection handlers enqueue without
waiting on program futures; completed futures hand writes to a separate bounded
response pool so waiting clients cannot starve controls.

`ProgramSession` centralizes request transactions, saving, and program switching
and release. It reads the current Program, GhidraState, and monitor from the
owning script. It does not keep a second copy of the current Program.
Handlers and helpers retain the session, not a
Program or monitor captured during construction. `JobScheduler` installs a fresh
`JobTaskMonitor` for each request and restores the script monitor in `finally`.
Control requests read snapshots and job records instead of this session.
Switching resolves the requested project file before checking whether it is
already open; two files can contain Programs with the same internal name.

The entry script calls its inherited `end(true)` before serving requests to end
the transaction created by `GhidraScript.executeNormal()`. Never end an unknown
transaction ID or leave the script's transaction ID tied to a switched program.
`CommandDispatcher` wraps each program request in a `ProgramSession` transaction,
ends it, and saves a changed program before returning a response. Read-only
requests do not write an unchanged database. Analysis and scripts follow the same
path, so there is no separate list of mutating command names to maintain.

`ProgramTransaction` remembers its Program and whether it is nested. Nested
handler aborts would roll back other changes in the same request, so they retain
partial changes as before; standalone transactions retain their requested
commit/rollback behavior. Handler mutations must use `session.transaction()`.
Earlier requests have already committed and saved. Failed requests also flush
retained changes and report `partial_changes_saved` in their error detail.

Saving uses a non-cancelled monitor after the request transaction ends, including
when execution was cancelled. Save errors fail the response, preserve the original
command response in error detail, and leave the program available for retry.
`program_save` retries the flush without restarting the bridge. Switching and
closing save before releasing the session's own consumer; a failed save or open
keeps the previous program. Shutdown drains requests, saves, and releases this
consumer on the script thread. Persistent startup runs the script without
`-process`, so even the initial program is opened and released by `ProgramSession`.
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

Handlers construct their domain results; the dispatcher applies the wire
envelope. Shared helpers contain lookup/serialization logic, not command routing.
Most implementation classes are package-private; only `BridgeRuntime` and
`ScriptAccess` cross the default-package entry point's boundary.

Keep the reflective OSGi loading in `ScriptCommands`: it avoids introducing
imports of Ghidra-internal packages that the source bundle cannot resolve. A
successful plain `javac` invocation does not validate this class-loader boundary.

## Validation

`bridge/sources.rs` tests source inventory/publication; `daemon_tests` exercises
runtime loading, control responsiveness, cancellation isolation, program switching,
and edits surviving failed mutations and restart. See [test commands](../../../../tests/README.md).
