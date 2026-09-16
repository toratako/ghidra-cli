# Runtime configuration and recovery

## Installation

Follow [the install steps](../README.md#install) using `ghidra-cli setup` or an
existing Ghidra 11+ installation. A full JDK is required (`javac` and
`jdk.compiler`, not a JRE); Ghidra 12.x requires JDK 21 (older releases accept
JDK 17). The CLI selects a suitable JDK automatically; `--java-home` overrides it.
Use `ghidra-cli setup --version 11.0` (or a patch release such as `11.0.1`)
to select a release number; omit `--version` to install the latest release.
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

## Project configuration

Project directory precedence is `--projects-dir DIR`, `GHIDRA_PROJECT_DIR`, config
`ghidra_project_dir`, then the default, for project management, doctor, and bridge
commands. The flag does not change the environment or saved configuration.
`GHIDRA_INSTALL_DIR` overrides the configured installation
for both doctor and execution.
Set a persistent JDK with `ghidra-cli config set java_home /opt/jdk-21`.
JDK selection precedence is `--java-home`, `GHIDRA_CLI_JAVA_HOME`, config
`java_home`, then automatic detection. Flag and environment overrides do not
change the saved value.
Project deletion removes the `.gpr`/`.rep` artifacts and an empty directory
reserved by `project create`; a nonempty same-named directory is retained.
Deletion first stops the CLI bridge and obtains Ghidra's project lock; another
Ghidra process using the project prevents deletion. Deleting `.gpr`/`.rep`
requires a working Ghidra/JDK installation; if it is unavailable, the project
files are retained. Removing an empty reservation does not launch Ghidra.
Ghidra 12.1+ rejects project paths containing dot-prefixed components; on Linux
the default falls back from the cache directory to `~/ghidra-cli-projects`.

Set default targets with `ghidra-cli config set default_project target` and
`ghidra-cli config set default_program target.bin`. Explicit command targets
override these saved defaults.

Configuration updates lock the resolved config target and atomically replace its
contents. Existing config symlinks remain links; a dangling link fails rather
than being replaced. Concurrent updates preserve unrelated settings.

Output precedence is explicit format, `--pretty`, `--json`, configured
`default_output_format`, then TTY detection (human-readable on TTY, compact JSON
otherwise). `default_limit` also applies after client filtering, sorting, and
offset when no explicit limit is given; `--count` and `--limit 0` bypass that cap.

## Environment

| Variable | Purpose |
|---|---|
| `GHIDRA_INSTALL_DIR` | Ghidra installation; also `config set ghidra_install_dir PATH` |
| `GHIDRA_PROJECT_DIR` | Base project directory |
| `GHIDRA_CLI_JAVA_HOME` | Full JDK override; also `--java-home` or `config set java_home PATH` |
| `GHIDRA_CLI_CONFIG` | Config file path override |
| `GHIDRA_DEFAULT_PROJECT` | Default project for `ghidra-cli query` |
| `GHIDRA_DEFAULT_PROGRAM` | Default program for `ghidra-cli query` and auto-selection |

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
| `GHIDRA_CLI_OP_TIMEOUT` | Long analyze/import/decompile socket waits, unset or 0 = unbounded |
| `GHIDRA_CLI_DECOMPILE_TIMEOUT` | Native Ghidra decompiler limit, unset or 0 = unbounded |
| `GHIDRA_CLI_READ_TIMEOUT` | Other request reads, 300; 0 = indefinite; includes queue wait |
| `GHIDRA_CLI_CONNECT_DEADLINE` | Connection retries, 60; minimum 1 |
| `GHIDRA_CLI_SHUTDOWN_TIMEOUT` | Total shutdown budget (lock, connection, reply, exit), 300; 0 = indefinite |

## Jobs and persistence

```bash
ghidra-cli start --project P --program bin
ghidra-cli status --project P
ghidra-cli jobs --project P
ghidra-cli jobs 42 --project P
ghidra-cli cancel 42 --project P
ghidra-cli restart --project P --program otherbin
ghidra-cli stop --project P
```

Commands needing the bridge start a per-project JVM on demand. Program jobs use
a FIFO of 256, with 100 recent jobs retained. `cancel` defaults to the active job;
queued cancellation is immediate, active cancellation cooperative. Socket read timeouts
return `Timeout:` with exit 75 while work stays running or queued; inspect `jobs`
before retrying a mutation. Shutdown rejects new work and drains accepted jobs, including a full queue.
The shutdown timeout reports an error (exit 75) and preserves discovery files and
the live process; it does not force termination. Inspect the process and retry
stop after accepted work finishes. Cancellation state is isolated per job, and
history retains metadata rather than completed response payloads.
If the final save fails, stop/restart/project deletion return an error and keep
the same JVM and program open. Resolve the cause, retry `program save`, then stop.

Program commands, including analysis, scripts, and each batch operation, save
before reporting success. Switching/closing also saves first; failure keeps the
program open. Before sending program commands to a bridge predating automatic
saving, the CLI attempts a save and bridge upgrade. Older bridges without final
save confirmation require the [manual upgrade procedure](#upgrading).

`program delete --program NAME` deletes the project file without selecting it.
Deleting the current program saves and closes it first; deleting another file
preserves the current selection. Other consumers and checkouts can prevent
deletion.

Save errors carry `detail.save_failed: true`; program commands also retain the
editing response in `detail.command_response`. Changes may remain in memory: keep the bridge running,
resolve the reported cause, and retry `program save` for the same project/program
without restarting or repeating the edit.
Saving a stopped bridge is a no-op. Auto-save covers the bridge's current program;
scripts that open other programs own their saving and release. Scripts must close
transactions they start.

Failed/cancelled operations can retain partial changes; saves of those changes
report `detail.partial_changes_saved: true`. Earlier successful requests are already
committed and saved. Cancellation cannot interrupt saving, so completion may follow it.

## Upgrading

Before replacing the CLI, run `ghidra-cli stop --project P` for each running
project using the old CLI and the same project path used to start it. Old PID-file
startup locks and new OS-backed lifecycle locks do not coordinate, so do not run
old and new CLI versions concurrently for a project. Start
bridges again after updating; old discovery keys are not preserved or migrated.
The current CLI requires the `shutdown_wait` protocol to confirm a final save.
It cannot safely stop an older bridge that only acknowledges shutdown acceptance;
save and stop that bridge with the old CLI before replacing it.
List-query filtering/paging also requires the CLI and Java bridge to match;
there is no query feature negotiation or old-server fallback. A bridge left
running during an update must be restarted before using the new CLI's queries.

## Installation failures

Use `-v`/`-vv`/`-vvv` for warn/info/debug logs; `--quiet` suppresses
non-essential output.

Run `ghidra-cli doctor` to check Ghidra, analyzeHeadless, project/config paths, the
selected full JDK, storage writes, loopback networking, and compilation of the
embedded Java bundle. Use `doctor --runtime` for runtime OSGi compatibility and
Ghidra's own startup writes.

Startup errors identify the operation and path where available. Import failures
also carry `detail.workflow_stage`, `project`, `import_status`, `analysis_status`,
and the saved `program` when known. A saved import is retained if later bridge
startup fails. Fix the reported cause and follow `detail.recovery` (an argument
array); do not re-import. `unknown` means completion was not confirmed. A timeout
can leave a job running: inspect `jobs` before retrying. Settings failures before
the Java script runs retain the launcher output instead of inventing a path.

Rust filesystem diagnostics include `detail.io_kind`, a stable snake_case
classification such as `read_only_filesystem`, `permission_denied`, or
`not_found` (`other` for unclassified kinds). `detail.os_error` is the native
numeric code when the I/O error exposes one, otherwise `null`. Wrappers such as
`tempfile` can retain the classification and message while hiding the numeric
code; use `io_kind` for automation instead of parsing the message. Temporary
file and directory management continues to use `tempfile`.

Linux/WSL may need X11 libraries even headless because initialization loads AWT.
For `libXtst.so.6` errors, install `libxtst` (Arch), `libxtst6` (Debian/Ubuntu), or
`libXtst` (Fedora/RHEL). On Arch/Debian, JDK 21 packages are `jdk21-openjdk` and
`openjdk-21-jdk`, respectively. WSL2 is preferable for compatibility.

On Linux, discovery files are `~/.local/share/ghidra-cli/bridge-{md5}.port` and
`.pid`, keyed by the canonical `.rep` directory. Liveness requires a valid port,
live PID, and TCP connectivity; `status` also pings the protocol.
Startup and shutdown clean stale discovery under an OS-backed lifecycle lock;
status only observes. The `.starting` lock file persists after release and must
not be deleted. Ghidra project lock files are never removed by CLI recovery;
do not manually delete them to bypass an owner. A live PID with missing or
unreachable discovery prevents cleanup/startup, and discovery PIDs are never
used for force termination. A busy program lane does not prove the bridge is
dead; inspect `jobs` before restarting.
