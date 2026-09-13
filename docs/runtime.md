# Runtime configuration and recovery

## Installation

For the basic install, see [README](../README.md#install).

Install Ghidra 11+ with `ghidra-cli setup`, or set `GHIDRA_INSTALL_DIR` to an existing
installation. A full JDK is required (`javac` and `jdk.compiler`, not a JRE);
Ghidra 12.x requires JDK 21 (older releases accept JDK 17). The CLI selects a
suitable JDK automatically; `--java-home` overrides it. `ghidra-cli doctor` checks the
installation and compiles the embedded bridge bundle.

## Project configuration

`--projects-dir DIR` overrides the `ghidra_project_dir` config key.
Ghidra 12.1+ rejects project paths containing dot-prefixed components; on Linux
the default falls back from the cache directory to `~/ghidra-cli-projects`.

## Environment

| Variable | Purpose |
|---|---|
| `GHIDRA_INSTALL_DIR` | Ghidra installation; also `config set ghidra_install_dir PATH` |
| `GHIDRA_PROJECT_DIR` | Base project directory |
| `GHIDRA_CLI_JAVA_HOME` | Full JDK override; also `--java-home` or config `java_home` |
| `GHIDRA_CLI_CONFIG` | Config file path override |
| `GHIDRA_DEFAULT_PROJECT` | Default project for `ghidra-cli query` |
| `GHIDRA_DEFAULT_PROGRAM` | Default program for `ghidra-cli query` and auto-selection |

Timeout values are seconds. A socket timeout does not cancel a server-side job.

| Variable | Budget and default |
|---|---|
| `GHIDRA_CLI_LAUNCH_TIMEOUT` | Bridge readiness, 180; also config `launch_timeout_secs` |
| `GHIDRA_CLI_OP_TIMEOUT` | Long analyze/import/decompile socket waits, unset or 0 = unbounded |
| `GHIDRA_CLI_DECOMPILE_TIMEOUT` | Native Ghidra decompiler limit, unset or 0 = unbounded |
| `GHIDRA_CLI_READ_TIMEOUT` | Other request reads, 300; 0 = indefinite; includes queue wait |
| `GHIDRA_CLI_CONNECT_DEADLINE` | Connection retries, 60; minimum 1 |
| `GHIDRA_CLI_SHUTDOWN_TIMEOUT` | Drain before force termination, 300; 0 = indefinite |

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

Commands that need the bridge start it on demand. Each project has its own JVM;
program jobs use a bounded FIFO (256), with the latest 100 jobs retained.
`cancel` without an ID targets the active job. Queued cancellation removes the
job immediately; active cancellation is cooperative. A socket read timeout
returns `Timeout:` with exit 75, while the job continues; inspect `jobs` before
retrying a mutation. Shutdown rejects new work and drains accepted jobs.

Program changes are saved before a command reports success. Analysis, scripts,
and individual batch operations use the same automatic saving. Switching or
closing a program also saves first; a save failure keeps that program open.
The CLI upgrades a running bridge that predates automatic saving before sending
program commands, using a normal stop/start to load the current Java bundle.

`program delete --program NAME` deletes the project file without selecting it.
Deleting the current program saves and closes it first; deleting another file
preserves the current selection. Other consumers and checkouts can prevent
deletion.

On a save failure, the error has `detail.save_failed: true` and preserves the
editing response in `detail.command_response`. Changes may still be in memory:
keep the bridge running, resolve the reported cause, and retry `program save`
for the same project/program. This saves without a restart or repeating the edit.
Saving a stopped bridge is a no-op. Auto-save covers the bridge's current program;
scripts that open other programs own their saving and release. Scripts must close
transactions they start.

Failed or cancelled operations can retain partial changes, which are also saved;
their error detail includes `partial_changes_saved: true` when a save occurred.
Earlier successful requests have already been committed and saved. Cancellation
does not interrupt the save of retained changes, so job completion can follow
the cancellation request. A timeout still leaves the job running or queued.

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

Port/PID discovery files live in `~/.local/share/ghidra-cli/bridge-{md5}.port`
and `.pid` on Linux, keyed by project path. Liveness checks require a valid port,
a live PID, and TCP connectivity; `status` additionally pings the protocol.
Startup/status/shutdown clean stale discovery files. A busy program lane is not
proof of a dead bridge; inspect `jobs` before restarting.
