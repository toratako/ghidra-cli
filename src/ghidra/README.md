# Ghidra bridge lifecycle

| File | Purpose |
|------|---------|
| `bridge.rs` | Persistent bridge reuse, discovery files, startup locking, liveness, and shutdown |
| `bridge/startup.rs` | Persistent child launch, output-reader lifetime, readiness, and failed-start cleanup |
| `bridge/import.rs` | Private one-shot import lifecycle, loader manifest, and completion receipt |
| `bridge/archive.rs` | GAR preflight, stopped-project lifecycle locking, bootstrap dispatch, and failure state |
| `bridge/diagnostics.rs` | Storage/loopback probes and disposable-project runtime check |
| `bridge/headless.rs` | Shared directory/JAR launch construction, Java environment selection, and compile diagnostics |
| `bridge/sources.rs` | Embedded Java source inventory, complete bundle publication, and diagnostic source staging |
| `installation.rs` | Installation resolution, shared file validation, diagnostics, and cited package layouts |
| `mod.rs` | Module root, `GhidraClient` for project/installation operations |
| `project.rs` | Project descriptor/data paths, persisted-data checks, and project-name enumeration |
| `scripts/GhidraCliBridge.java` | GhidraScript entry point and access to inherited script state |
| `scripts/ghidracli/` | Java runtime, transport, scheduling, program session, and command handlers; see [Java bridge map](scripts/ghidracli/README.md) |

Persistent startup and one-shot imports share launcher/JDK selection but own
their process and stream lifetimes separately.

## Installation selection

`installation::resolve` selects a validated runtime descriptor with its format,
canonical path, version, minimum Java version, and source. Config lookup
delegates to it; startup and doctor reuse the resolved descriptor for launch
construction, compilation, and runtime probes without rediscovering or
revalidating an installation from its path.

Directory validation checks the platform launcher,
`Ghidra/application.properties`, `Utility.jar`, and `LaunchSupport.jar`; it accepts
distro release names such as `DEV` and `NIX`. Explicit standalone JAR selection
checks the archive's official entry point and embedded
`_Root/Ghidra/application.properties` without starting Java. Compilation uses the
distribution libraries or the selected standalone JAR as appropriate.
JVM/native compatibility remains doctor's responsibility; successful archive
inspection or `javac` alone does not establish runtime compatibility.

`package_roots` and `Platform::commands` cite the upstream package definitions
and prefix documentation beside their paths. Windows entries cite the previous
CLI implementation: they are retained heuristics, not vendor default paths.
Add a layout only with evidence for the actual installed distribution root.
The runtime selection policy is documented in [runtime configuration](../../docs/runtime.md#project-configuration).

Tests in `installation/tests.rs` inject environment values, PATH, and search
roots, using temporary distributions instead of host installations. CLI tests
cover diagnostics and overrides; `bootstrap_tests` validates real PATH discovery,
JVM startup, and disposable-project cleanup on the native CI platforms.
`standalone_jar_tests` builds the official default JAR, relocates it outside the
distribution, and exercises the same runtime through `GHIDRA_JAR`.

## Startup and import

`ensure_bridge_running()` holds the startup lock across liveness recheck,
stale-file cleanup, and `startup::start_bridge()`. Startup owns the child and
output readers until readiness or completed failure cleanup. After readiness, a
detached waiter reaps the child when it exits; stopping a running bridge waits for
the discovery PID to exit without force-killing it. `BridgeStartMode::Process { program_name }` opens
an existing program through `ProgramSession`; `Project` leaves it unselected.
Both use the same headless arguments:

```text
<headless-entry-point> <project_dir> <project_name> -noanalysis
  -scriptPath <bundle-dir> -preScript GhidraCliBridge.java <port_file_path> [<program>]
```

The directory entry point is `support/analyzeHeadless` (`.bat` on Windows).
The standalone entry point is the selected JDK's `java -jar <ghidra.jar>` with
headless JVM settings. Persistent startup, import, project bootstraps, and doctor
share this construction; only the runtime format determines the entry point.
Running bridges keep their original JVM until stopped or restarted.

Omit `-process`: it leaves a headless-owned reference to the initial program that
prevents deletion until shutdown. The bridge opens the requested program before
publishing readiness, owns its release, and also supports empty existing projects.
Missing projects are rejected before launching.

Launch readiness is bounded and excludes analysis. Fresh imports use a separate
short-lived headless run with `-noanalysis -preScript GhidraCliBootstrap.java`.
The script reads a private JSON manifest and uses `ImportSupport` to load with the
requested saved name, optionally analyze in an owned transaction, save, and release
before exiting. Rust requires both successful exit and a structured completion
receipt; it never infers success from an unrelated log line. The persistent bridge
then opens the saved program; `--no-analyze` disables import analysis.
Explicit loader/language/compiler options always take this one-shot path,
stopping a live bridge first, so `BinaryLoader`, `x86:LE:32:default`, and
`baseAddr` reach the loader. Best-guess imports into an already-open project use
the same `ImportSupport` save/name boundary followed by TCP analysis. Explicit
name collisions fail before loading; omitted names can use Ghidra's collision
suffix. Import input paths are absolute without resolving symlinks, preserving
the supplied file name as the default saved name in both routes.
Always return the saved DomainFile name.
Loader option names are checked against the selected loader's default option
arguments before import; unknown names fail with `import_status: not_started`.
Ghidra's importer alone only logs and ignores those names.

Rust writes the child PID immediately after spawn (best effort), enabling orphan
cleanup even if Java fails before binding. Java binds `ServerSocket(0)` on
localhost, writes the port/PID files authoritatively, and signals
`{"status":"ready"}`. On failure/timeout, kill and reap the whole process group
before joining output-reader threads: a surviving JVM grandchild can keep pipes
open indefinitely. Preserve stdout/stderr diagnostics and remove stale files.
Java startup failures publish a `GHIDRA_CLI_STARTUP_ERROR` JSON diagnostic with
stage, path, and cause before cleanup. Rust filesystem failures carry the same
fields; the import workflow adds its saved/analysis checkpoint without losing
the underlying operation or timeout classification.

## Java source publication

`bridge/sources.rs` embeds the complete tree. Startup stages it privately then
publishes by directory rename to
`~/.config/ghidra-cli/bridge-sources/<content-hash>/`. Identical bundles are reused;
content changes get new paths so concurrent projects/builds cannot mix revisions.
Keep old bundles while JVMs may still use them.

Register every new Java file in that inventory. `doctor` compiles it in a
temporary tree; unit tests check source coverage. Real Ghidra tests are required
for OSGi resolution, which plain `javac` cannot validate.

## Discovery, liveness, and shutdown

Discovery files are `bridge-{md5}.port` / `.pid` in the platform data directory
(`~/.local/share/ghidra-cli/` on Linux), keyed by the `.rep` directory's volume/file
ID on Windows and canonical location elsewhere. Lifecycle locks share this identity. The persistent `.starting` file carries an
OS-backed exclusive lock across start, stop, and stale-discovery cleanup. Keep
the file after release: unlinking it would let waiters lock different files.
Windows falls back to canonical location if file IDs are unusable; missing
projects use absolute paths. See the
[upgrade procedure](../../docs/runtime.md#upgrading) before replacing a CLI
while bridges are running.

- `is_bridge_running()` checks a valid port, valid/live PID, and TCP connectivity,
  returning the port from that check to avoid a separate discovery-file read.
- `bridge_status()` uses `BridgeClient::ping()` for protocol-level verification.
- `stop_bridge()` uses deadline-aware shutdown and waits for accepted jobs to
  drain, the final save to succeed, and the JVM to exit. A save failure restores
  request acceptance and retains the same program/JVM for recovery. One budget
  includes lifecycle-lock acquisition,
  connection, reply, and exit. Expiry returns the typed timeout (exit 75),
  preserving discovery and the live process; discovery PIDs are never force-killed.
- `delete_project()` holds that lifecycle lock across stop and removal. A bootstrap
  in a disposable project acquires the target's Ghidra `LockFactory` lock before
  removing `.rep`/`.gpr`; an external Ghidra owner prevents deletion. It releases
  only its own lock and leaves bare project directories intact.
- GAR creation holds the lifecycle lock across confirmed final-save shutdown
  and a bootstrap holding the target's Ghidra lock. An exited PID without a save
  acknowledgement is an error. Archive preflight rejects existing output before
  stopping; the bootstrap rechecks under its lock. Restoration locks the new
  target without opening a bridge and rejects either existing project artifact.
  Rust resolves project/output parents and the archive input through the filesystem
  before selecting lifecycle locks; Java preserves those resolved paths.
  GAR errors retain the actual bridge state and underlying timeout/save detail.
- Startup and shutdown clean stale port/PID files only under the lifecycle lock.
  A live recorded PID prevents cleanup even if its port is unreachable. Status
  is observational and does not clean files.
- Never remove Ghidra project locks during recovery. Missing discovery does not
  establish ownership of those locks. The old PID-file startup-lock protocol
  does not coordinate with OS locks: stop with the old CLI before upgrading.

Only liveness probes use raw TCP; commands use [BridgeClient](../ipc/README.md).
A busy program lane is not evidence of a dead bridge. See the
[runtime reference](../../docs/runtime.md) for timeout knobs and recovery.

## Cross-platform paths

- Use `Path`/`PathBuf` joins and platform-specific launcher/executable names.
- Discovery, startup locks, shutdown, and test harnesses must share bridge
  helpers. Projects use sibling `.gpr`/`.rep` artifacts; the bare path may not
  exist. Absolute paths alone do not resolve case or directory aliases, and
  unconditional lowercasing can merge distinct projects.
- Pass OS paths as individual `Command` arguments. Quote generated CLI batch
  paths for its parser; cover spaces, apostrophes, and backslashes.
- Wait for JVM exit and close file handles before deleting or reopening files;
  Windows can retain project/file locks after a shutdown request.

See [native-platform validation](../../tests/README.md#cross-platform-changes).
