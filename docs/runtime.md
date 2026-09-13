# Runtime configuration and recovery

## Installation

For the basic install, see [README](../README.md#install).

Install Ghidra 11+ with `ghidra setup`, or set `GHIDRA_INSTALL_DIR` to an existing
installation. A full JDK is required (`javac` and `jdk.compiler`, not a JRE);
Ghidra 12.x requires JDK 21 (older releases accept JDK 17). The CLI selects a
suitable JDK automatically; `--java-home` overrides it. `ghidra doctor` checks the
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
| `GHIDRA_DEFAULT_PROJECT` | Default project for `ghidra query` |
| `GHIDRA_DEFAULT_PROGRAM` | Default program for `ghidra query` and auto-selection |

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
ghidra start --project P --program bin
ghidra status --project P
ghidra jobs --project P
ghidra jobs 42 --project P
ghidra cancel 42 --project P
ghidra restart --project P --program otherbin
ghidra stop --project P
```

Commands that need the bridge start it on demand. Each project has its own JVM;
program jobs use a bounded FIFO (256), with the latest 100 jobs retained.
`cancel` without an ID targets the active job. Queued cancellation removes the
job immediately; active cancellation is cooperative. A socket read timeout
returns `Timeout:` with exit 75, while the job continues; inspect `jobs` before
retrying a mutation. Shutdown rejects new work and drains accepted jobs.

Edits may remain in memory under Ghidra's headless transaction. `program save`
stops and restarts the bridge to flush them; `stop` flushes without restarting.
`program close` is not a substitute for this flush. Failed mutations inside the
headless transaction can retain partial changes: aborting the nested transaction
would also erase earlier successful requests. Do not assume per-request rollback.
Standalone transactions can roll back; the initially loaded program and programs
opened later can have different transaction lifetimes.

## Installation failures

Use `-v`/`-vv`/`-vvv` for warn/info/debug logs; `--quiet` suppresses
non-essential output.

Run `ghidra doctor` to check Ghidra, analyzeHeadless, project/config paths, the
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
