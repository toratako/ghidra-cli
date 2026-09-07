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
and shutdown. `JobScheduler` owns queue state, job retention, cancellation, and
published status snapshots. It never waits for socket writes on the program
thread. Shutdown closes the listener, rejects new program jobs, and drains
accepted jobs before returning to Ghidra.

`ProgramSession` centralizes program switching/release and reads the current
Program, GhidraState, and monitor from the owning script. It does not keep a second
copy of the current Program. Handlers and helpers retain the session, not a
Program or monitor captured during construction. `JobScheduler` installs a fresh
`JobTaskMonitor` for each request and restores the script monitor in `finally`.
Control requests read snapshots and job records instead of this session.
Switching resolves the requested project file before checking whether it is
already open; two files can contain Programs with the same internal name.

`ProgramTransaction` remembers the Program and whether an outer transaction
already existed when a handler began. An inner abort would mark the entire
Ghidra transaction group for rollback, losing earlier successful commands.
Therefore a failed nested handler ends its transaction without aborting the
outer group. Partial changes from the failed handler can remain; this does not
provide atomic rollback per request. Standalone transactions retain their
requested commit/rollback behavior. Handler mutations must use
`session.transaction()` rather than calling `Program.startTransaction()` directly.

The headless harness holds an outer transaction for the initially loaded program
while the bridge script runs. Returning from the script lets the harness commit
and save that program. `ghidra program save` stops and restarts the bridge to
obtain this durable flush. A program explicitly opened by `ProgramSession` can
have a different transaction lifetime; do not assume every Program has the
harness's outer transaction.

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

Source publication/inventory tests are in `bridge/sources.rs`. Integration tests
use the real Ghidra bridge: `daemon_tests` covers startup, restart, control
responsiveness, queued/active cancellation, Program switching/close, and edits
surviving a failed mutation and restart. Domain suites cover command behavior.
Run `cargo test` with `GHIDRA_INSTALL_DIR` pointing to an installed Ghidra; absence
of Ghidra is a test failure, never a skip. Final checks also include
`cargo fmt --all -- --check` and `cargo clippy -- -D warnings`.
