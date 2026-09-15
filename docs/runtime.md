# Runtime configuration and recovery

## Installation

Follow [the install steps](../README.md#install) using `ghidra-cli setup` or an
existing Ghidra 11+ installation. A full JDK is required (`javac` and
`jdk.compiler`, not a JRE); Ghidra 12.x requires JDK 21 (older releases accept
JDK 17). The CLI selects a suitable JDK automatically; `--java-home` overrides it.
`ghidra-cli doctor` checks the installation and compiles the embedded bridge bundle.
Setup downloads and extracts into private staging, validates the installation,
and publishes it only when complete. It reuses a valid existing installation and
refuses an incomplete existing destination; inspect that directory before moving
or removing it and retrying. Saved installation paths are absolute.

## Project configuration

`--projects-dir DIR` overrides config `ghidra_project_dir` for project management
and bridge commands. `GHIDRA_INSTALL_DIR` overrides the configured installation
for both doctor and execution.
Project deletion removes the `.gpr`/`.rep` artifacts and an empty directory
reserved by `project create`; a nonempty same-named directory is retained.
Ghidra 12.1+ rejects project paths containing dot-prefixed components; on Linux
the default falls back from the cache directory to `~/ghidra-cli-projects`.

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
| `GHIDRA_CLI_JAVA_HOME` | Full JDK override; also `--java-home` or config `java_home` |
| `GHIDRA_CLI_CONFIG` | Config file path override |
| `GHIDRA_DEFAULT_PROJECT` | Default project for `ghidra-cli query` |
| `GHIDRA_DEFAULT_PROGRAM` | Default program for `ghidra-cli query` and auto-selection |

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

Program commands, including analysis, scripts, and each batch operation, save
before reporting success. Switching/closing also saves first; failure keeps the
program open. Before sending program commands to a bridge predating automatic
saving, the CLI upgrades it with a normal stop/start of the current Java bundle.

`program delete --program NAME` deletes the project file without selecting it.
Deleting the current program saves and closes it first; deleting another file
preserves the current selection. Other consumers and checkouts can prevent
deletion.

Save errors carry `detail.save_failed: true` and the editing response in
`detail.command_response`. Changes may remain in memory: keep the bridge running,
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

## Installation failures

Use `-v`/`-vv`/`-vvv` for warn/info/debug logs; `--quiet` suppresses
non-essential output.

Run `ghidra-cli doctor` to check Ghidra, analyzeHeadless, project/config paths, the
selected full JDK, and compilation of the embedded Java bundle. A successful
`javac` check alone does not establish runtime OSGi compatibility.

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
