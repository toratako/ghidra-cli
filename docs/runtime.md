# Runtime configuration and recovery

## Installation

Follow [the install steps](../README.md#install) using `ghidra-cli setup` or an
existing Ghidra 11+ installation. A full JDK is required (`javac` and
`jdk.compiler`, not a JRE); Ghidra 12.x requires JDK 21 (older releases accept
JDK 17). The CLI selects a suitable JDK automatically; `--java-home` overrides it.
Use `setup --skip-java-check` to install Ghidra before a JDK is available;
running Ghidra still requires a suitable full JDK.
On macOS, build Ghidra's native components after extracting a release; the
archive does not include the macOS decompiler. Follow Ghidra's
[native build instructions](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.3_build/GhidraDocs/GettingStarted.md#building-native-components)
(`./gradlew buildNatives` in the installation's `support/gradle` directory).
CI builds these tools before caching its macOS installation.
`find bytes --regex` requires Ghidra's native `memsearch` API, introduced in
Ghidra 11.2. Installations without it report an error for that command; other
commands remain available.
`ghidra-cli doctor` checks the installation, compiles the embedded Java bundle,
probes storage with temporary create/write/rename/delete operations, and tests
loopback TCP bind/connect. It reports resolved paths and their configuration
sources. These checks do not establish that the JVM can start; the runtime check
is explicitly `not_checked` unless `--runtime` is supplied.
`ghidra-cli doctor --runtime` also creates a disposable project in the configured
project directory, starts and pings the real bridge, then stops it and removes
the project. It uses the actual environment and settings/cache locations; it may
populate Ghidra's normal caches. If shutdown fails, it retains the diagnostic
project and reports its location. Prerequisite failures prevent the runtime probe.
Setup downloads and extracts into private staging, validates the installation,
and publishes it only when complete. It reuses a valid existing installation and
refuses an incomplete existing destination; inspect that directory before moving
or removing it and retrying. Saved installation paths are absolute.
Setup preserves archive file modification times: Ghidra uses them to decide
whether compiled `.sla` language definitions need rebuilding. Older CLI versions
discarded these times, which can trigger unnecessary recompilation on import.
To replace an affected installation, stop its running bridges and install the
same Ghidra release into a new directory with `setup --version VERSION --dir DIR`.
Setup selects the new installation in config; update `GHIDRA_INSTALL_DIR` too if
it is set. Reusing the old directory does not repair its file times.

## Project configuration

Project directory precedence is `--projects-dir DIR`, `GHIDRA_PROJECT_DIR`, config
`ghidra_project_dir`, then the default, for project management, doctor, and bridge
commands. The flag does not change the environment or saved configuration.
Ghidra selection is `GHIDRA_INSTALL_DIR`, config `ghidra_install_dir`, then
automatic detection. Explicit paths are validated; an empty or invalid override
fails instead of selecting another installation. Doctor reports the effective
path, source, and version. `config get/list` shows saved settings only.

Detection checks absolute PATH entries in order, resolving Ghidra launcher
symlinks and Homebrew's package layout without executing wrappers. If PATH does
not identify an installation, it checks the known Arch, Kali/Pentoo, Void,
Homebrew, and MacPorts layouts, or the existing Windows search locations.
Homebrew's `HOMEBREW_PREFIX` is also recognized. Nix installations are found
through their PATH symlinks. Multiple distinct installations at the same priority
are an error: select one with `config set ghidra_install_dir PATH` (or fix an
existing environment override). Detection does not choose the newest version or
save its result. Arbitrary ZIP extraction locations require PATH or an explicit
setting; the filesystem and setup's installation directory are not searched.
See the [installation implementation and layout sources](../src/ghidra/README.md#installation-selection).

Set a persistent JDK with `ghidra-cli config set java_home /opt/jdk-21`.
JDK selection precedence is `--java-home`, `GHIDRA_CLI_JAVA_HOME`, config
`java_home`, then automatic detection. Flag and environment overrides do not
change the saved value.
Project listing and existence checks recognize `.gpr`/`.rep` artifacts.
Deletion removes those artifacts and leaves same-named bare directories intact.
Deletion first stops the CLI bridge and obtains Ghidra's project lock; another
Ghidra process using the project prevents deletion. Deleting `.gpr`/`.rep`
requires a working Ghidra/JDK installation; if it is unavailable, the project
files are retained.
Ghidra 12.1+ rejects project paths containing dot-prefixed components; on Linux
the default falls back from the cache directory to `~/ghidra-cli-projects`.

Configuration updates lock the resolved config target and atomically replace its
contents. Existing config symlinks remain links; a dangling link fails rather
than being replaced. Concurrent updates preserve unrelated settings.

Output precedence is explicit format, `--pretty`, `--json`, configured
`default_output_format`, then TTY detection (human-readable on TTY, compact JSON
otherwise). For newline-delimited JSON, use `--format ndjson` or
`config set default_output_format ndjson`.
`default_limit` also applies after client filtering, sorting, and
offset when no explicit limit is given; `--count` and `--limit 0` bypass that cap.

Set defaults with `ghidra-cli config set default_project target` and
`ghidra-cli config set default_program target.bin`. Project selection uses
`--project`, then `default_project`. Explicit
`--program` selects a program; a running bridge otherwise keeps its current
selection. When starting a bridge, config `default_program` supplies the default
program if no explicit program was given.

## Environment

| Variable | Purpose |
|---|---|
| `GHIDRA_INSTALL_DIR` | Ghidra installation; also `config set ghidra_install_dir PATH` |
| `GHIDRA_PROJECT_DIR` | Base project directory |
| `GHIDRA_CLI_JAVA_HOME` | Full JDK override; also `--java-home` or `config set java_home PATH` |
| `GHIDRA_CLI_CONFIG` | Config file path override |

On Linux, `XDG_CONFIG_HOME` controls the CLI configuration and Java source bundle,
and `XDG_DATA_HOME` controls bridge discovery/lock files and CLI logs.
`GHIDRA_CLI_CONFIG` changes only the YAML file, not these other locations.
Ghidra also uses settings and caches; its version-specific paths are reported by
`doctor --runtime`. Set `XDG_CONFIG_HOME` and `XDG_CACHE_HOME` before launching it
when the default locations are inaccessible. Other platforms use their native
directory conventions; inspect the paths in the doctor report.

For a restricted Linux workspace, choose absolute writable paths, for example:

```bash
export XDG_CONFIG_HOME="$PWD/tmp/analysis/config"
export XDG_CACHE_HOME="$PWD/tmp/analysis/cache"
export XDG_DATA_HOME="$PWD/tmp/analysis/data"
export GHIDRA_PROJECT_DIR="$PWD/tmp/analysis/projects"
export GHIDRA_INSTALL_DIR=/opt/ghidra
ghidra-cli doctor --runtime
```

Use the same environment for subsequent commands so they find the same bridge.
Directory overrides do not grant loopback networking permission. If a sandbox
denies `127.0.0.1` bind/connect, obtain permission for the affected command from
the environment running the CLI. The CLI does not change sandbox policy.

Timeout values are seconds.

| Variable | Budget and default |
|---|---|
| `GHIDRA_CLI_LAUNCH_TIMEOUT` | Bridge readiness, 180; also config `launch_timeout_secs` |
| `GHIDRA_CLI_OP_TIMEOUT` | Long analyze/import/decompile, high p-code, variable-edit and return-type-edit socket waits, unset or 0 = unbounded |
| `GHIDRA_CLI_DECOMPILE_TIMEOUT` | Native limit for `decompile`, `pcode function --high`, `function edit-var` and `function set-return-type`; unset or 0 = unbounded, maximum 2,147,483 seconds |
| `GHIDRA_CLI_READ_TIMEOUT` | Other request reads, 300; 0 = indefinite; includes queue wait |
| `GHIDRA_CLI_CONNECT_DEADLINE` | Connection retries, 60; minimum 1 |
| `GHIDRA_CLI_SHUTDOWN_TIMEOUT` | Total shutdown budget (lock, connection, reply, exit), 300; 0 = indefinite |

Invalid native decompiler budgets are errors. The maximum prevents overflow in
Ghidra's conversion from seconds to milliseconds; use 0 for an unlimited budget.

## Jobs and persistence

```bash
ghidra-cli bridge start --project P --program bin
ghidra-cli bridge status --project P
ghidra-cli bridge ping --project P
ghidra-cli job list --project P
ghidra-cli job get 42 --project P
ghidra-cli job cancel 42 --project P
ghidra-cli bridge restart --project P --program otherbin
ghidra-cli bridge stop --project P
```

Commands needing the bridge start a per-project JVM on demand. Program jobs use
a FIFO of 256, with 100 recent jobs retained. `job cancel` defaults to the active
job; queued cancellation is immediate, active cancellation cooperative. Socket
read timeouts return `Timeout:` with exit 75 while work stays running or queued;
inspect `job list` before retrying a mutation. Shutdown rejects new work and
drains accepted jobs, including a full queue.
The shutdown timeout reports an error (exit 75) and preserves discovery files and
the live process; it does not force termination. Inspect the process and retry
stop after accepted work finishes. Cancellation state is isolated per job, and
history retains metadata rather than completed response payloads.
If the final save fails, stop/restart/project deletion return an error and keep
the same JVM and program open. Resolve the cause, retry `program save`, then stop.

Program commands, including analysis, scripts, and each batch operation, save
before reporting success. Switching/closing also saves first; failure keeps the
program open. For a bridge from another build, follow [upgrading](#upgrading).

`program delete --program NAME` deletes the project file without selecting it.
Deleting the current program saves and closes it first; deleting another file
preserves the current selection. Other consumers and checkouts can prevent
deletion.

Save errors carry `detail.save_failed: true`; program commands also retain the
editing response in `detail.command_response`. A save failure is returned without
an implicit retry in that request. Changes may remain in memory: keep the bridge running,
resolve the reported cause, and retry `program save` for the same project/program
without restarting or repeating the edit.
Saving a stopped bridge is a no-op. Auto-save covers the bridge's current program;
scripts that open other programs own their saving and release. Scripts must close
transactions they start.

Ordinary program requests are atomic: failure or cancellation rolls back every
change in that request, including clearing before redisassembly and multi-symbol
deletion. Errors report `detail.rolled_back: true`, plus `detail.cancelled: true`
when cancelled. Earlier completed requests remain intact. Batch commands run
sequentially with these individual boundaries; a batch is not one transaction.
A rolled-back request does not save pending edits from an earlier save failure.
Transaction-boundary failures, save failures, and timeouts always stop a batch,
including nested batches; completed rollbacks follow its `--on-error` policy.

Analysis, scripts, imports, exports, and program open/close/save/delete are explicit
exceptions. They can retain partial changes and external file/project effects;
saved partial changes report `detail.partial_changes_saved: true`. Cancellation
cannot interrupt saving after commit, so completion may follow it.

`detail.transaction_failed: true` means the bridge could not establish or finish
transaction ownership; it does not confirm rollback. An ordinary request is
rejected before execution if another script left a transaction active, preserving
that owner's transaction and edits. If native code instead leaves a child
transaction open during an atomic request, the bridge marks its own root aborted;
rollback remains pending until the child's owner closes it. Those request edits
cannot be committed or saved. Keep the bridge running and resolve the outstanding
transaction through its owner before retrying; recovery scripts remain available.
The bridge never ends an unknown transaction to force recovery.

## Upgrading

Before replacing the CLI, run `ghidra-cli bridge stop --project P` for each running
project. Stop waits for accepted jobs to finish and pending changes to save; resolve
any save failure before updating. Start bridges again after updating so the CLI
and running Java bridge use the same build. Do not run different CLI versions
concurrently for the same project.

Program dispatch requires `bridge_info.explicit_addresses: true`,
`auto_save: true`, and `atomic_edits: true`. The CLI rejects a bridge missing a
required capability before sending program commands. It does not restart or
replay a failed command automatically. Explicit `program save` bypasses this
gate so pending edits can be saved in place before an explicit bridge restart.

## Installation failures

Use `-v`/`-vv`/`-vvv` for warn/info/debug logs; `--quiet` suppresses
non-essential output.

Start with `ghidra-cli doctor`; use `doctor --runtime` for OSGi compatibility and
Ghidra's startup writes (see [installation](#installation) for probe side effects).

Startup errors identify the operation and path where available. Import failures
also carry `detail.workflow_stage`, `project`, `import_status`, `analysis_status`,
and the saved `program` when known. A saved import is retained if later bridge
startup fails. Fix the reported cause and follow `detail.recovery` (an argument
array); do not re-import. `unknown` means completion was not confirmed. A timeout
can leave a job running: inspect `job list` before retrying. Settings failures before
the Java script runs retain the launcher output instead of inventing a path.

Rust filesystem diagnostics include `detail.io_kind`, a stable snake_case
classification such as `read_only_filesystem`, `permission_denied`, or
`not_found` (`other` for unclassified kinds). `detail.os_error` is the native
numeric code when the I/O error exposes one, otherwise `null`. Use `io_kind` for
automation instead of parsing messages; wrappers can hide the numeric code while
retaining the classification.

Linux/WSL may need X11 libraries even headless because initialization loads AWT.
For `libXtst.so.6` errors, install `libxtst` (Arch), `libxtst6` (Debian/Ubuntu), or
`libXtst` (Fedora/RHEL). On Arch/Debian, JDK 21 packages are `jdk21-openjdk` and
`openjdk-21-jdk`, respectively. WSL2 is preferable for compatibility.

On Linux, discovery files are `~/.local/share/ghidra-cli/bridge-{md5}.port` and
`.pid`, keyed by the canonical `.rep` directory. Liveness requires a valid port,
live PID, and TCP connectivity; `bridge status` also pings the protocol.
Startup and shutdown clean stale discovery under an OS-backed lifecycle lock;
`bridge status` only observes. The `.starting` lock file persists after release and must
not be deleted. Ghidra project lock files are never removed by CLI recovery;
do not manually delete them to bypass an owner. A live PID with missing or
unreachable discovery prevents cleanup/startup, and discovery PIDs are never
used for force termination. A busy program lane does not prove the bridge is
dead; inspect `job list` before restarting.
