# Ghidra bridge lifecycle

| File | Purpose |
|------|---------|
| `bridge.rs` | Persistent bridge reuse, discovery files, startup locking, liveness, and shutdown |
| `bridge/startup.rs` | Persistent child launch, output-reader lifetime, readiness, and failed-start cleanup |
| `bridge/import.rs` | Private one-shot headless import lifecycle and loader arguments |
| `bridge/headless.rs` | Private launcher discovery, Java environment selection, and compile diagnostics |
| `bridge/sources.rs` | Embedded Java source inventory, complete bundle publication, and diagnostic source staging |
| `setup.rs` | Ghidra download, installation, Java version check |
| `mod.rs` | Module root, `GhidraClient` for project/installation operations |
| `project.rs` | Project descriptor/data paths, persisted-data checks, and project-name enumeration |
| `scripts/GhidraCliBridge.java` | GhidraScript entry point and access to inherited script state |
| `scripts/ghidracli/` | Java runtime, transport, scheduling, program session, and command handlers; see [Java bridge map](scripts/ghidracli/README.md) |

`bridge.rs` re-exports `start_bridge`, `OneShotImportOptions`, `import_oneshot`,
`compile_check`, and `find_headless_script`, preserving existing public import
paths. Persistent startup and one-shot imports share launcher/JDK selection;
their process and stream lifetimes remain owned by their respective workflows.

`ensure_bridge_running()` holds the startup lock across its liveness recheck,
stale-file cleanup, and call to `startup::start_bridge()`. The startup module owns
the child and both output readers until readiness or completed failure cleanup;
stopping an already-running bridge uses the discovery PID in `bridge.rs`.

## Startup and import

`ensure_bridge_running()` reuses a live bridge or removes stale discovery files
and starts one. `BridgeStartMode::Process { program_name }` opens an existing
program through `ProgramSession`; `Project` opens the project without selecting one.
Both launch with:

```text
analyzeHeadless <project_dir> <project_name> -noanalysis
  -scriptPath <bundle-dir> -preScript GhidraCliBridge.java <port_file_path> [<program>]
```

Omit `-process`: it leaves a headless-owned reference to the initial program that
prevents deletion until shutdown. The bridge opens the requested program before
publishing readiness, owns its release, and also supports empty existing projects.
Missing projects are rejected before launching.

Launch readiness is bounded and excludes analysis. Fresh imports use a separate
short-lived `analyzeHeadless -import` run that analyzes and commits before the
persistent bridge opens the program; `--no-analyze` disables that analysis.
Explicit loader/language/compiler options always take this one-shot path,
stopping a live bridge first, so `BinaryLoader`, `x86:LE:32:default`, and
`baseAddr` reach the headless loader. Best-guess imports into an already-open
project may use bridge `AutoImporter` followed by TCP analysis.

Rust writes the child PID immediately after spawn (best effort), enabling orphan
cleanup even if Java fails before binding. Java binds `ServerSocket(0)` on
localhost, writes the port/PID files authoritatively, and signals
`{"status":"ready"}`. On failure/timeout, kill and reap the whole process group
before joining output-reader threads: a surviving JVM grandchild can keep pipes
open indefinitely. Preserve stdout/stderr diagnostics and remove stale files.

## Java source publication

`bridge/sources.rs` embeds the complete tree. Startup stages it privately then
publishes by directory rename to
`~/.config/ghidra-cli/bridge-sources/<content-hash>/`. Identical bundles are reused;
content changes get new paths so concurrent projects/builds cannot mix revisions.
Keep old bundles while JVMs may still use them. Startup no longer reads the old
single-file `scripts/` directory.

Register every new Java file in that inventory. `doctor` compiles the same
inventory in a temporary tree. The inventory unit test checks source coverage;
real Ghidra integration tests check OSGi resolution, which plain `javac` cannot.

## Discovery, liveness, and shutdown

Each project path hashes to `bridge-{md5}.port` / `.pid` in the platform data
directory (`~/.local/share/ghidra-cli/` on Linux). Discovery and startup locking
identify the `.rep` directory: its volume/file ID on Windows and its canonical
location elsewhere. This preserves distinct projects while resolving Windows
case variations and directory aliases. Missing projects use an absolute path
without requiring files to exist. Windows falls back to the canonical location
on filesystems that do not provide usable file IDs. See the
[upgrade procedure](../../docs/runtime.md#upgrading) before replacing a CLI
while bridges are running.

- `is_bridge_running()` checks a valid port, valid/live PID, and TCP connectivity,
  returning the port from that check to avoid a separate discovery-file read.
- `bridge_status()` uses `BridgeClient::ping()` for protocol-level verification.
- `stop_bridge()` uses `BridgeClient::shutdown()`, waits for accepted jobs to
  drain, then force-terminates the process group if the grace period expires.
- Startup, failed liveness/status checks, and shutdown remove stale port/PID files.

Only lightweight liveness probes use raw TCP here; command traffic goes through
[BridgeClient](../ipc/README.md). A busy program lane is not evidence of a dead
bridge. Networking, responsive controls, and the serialized GhidraScript lane
are described in the [Java bridge map](scripts/ghidracli/README.md); timeout knobs
and operational recovery are in the [runtime reference](../../docs/runtime.md).
