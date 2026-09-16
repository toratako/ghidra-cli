# Changelog

Release history follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `find instruction PATTERN` searches existing Ghidra instruction text with
  case-insensitive literal matching, optional `--case-sensitive`, and inclusive
  `--start`/`--end` bounds. It supports the usual query options and cancellation;
  it neither disassembles undefined bytes nor requires cross-references.
- `disasm TARGET --end END` lists existing instructions whose start addresses
  lie in the inclusive range. It rejects `--instructions` together with `--end`,
  reversed ranges, and bounds in different address spaces. Range queries honor
  `--limit` (including zero), filtering, sorting, offsets, and counts.

### Changed

- `batch` writes attempted results to stdout even on partial failure, preserving
  nonzero exit codes and stop policies. Stderr no longer carries `detail.results`.
- `find calls TARGET` searches the selected program for incoming call sites;
  `function calls TARGET` retains outgoing calls. Resolved thunks and import
  pointers are followed without treating ordinary data references as calls.
- `doctor` checks storage writes and loopback TCP. `doctor --runtime` also creates
  a disposable project, starts and pings Ghidra, and verifies clean shutdown.
- Removed `--detach` from import and analysis; commands wait for completion.
- Bridge lifecycle operations use persistent OS-backed `.starting` locks. Stop
  every running bridge with the old CLI before upgrading: old and new lock
  protocols cannot coordinate. Recovery never deletes Ghidra project locks or
  force-terminates an unverified discovery PID.
- Shutdown uses one total timeout across lock acquisition, connection, response,
  and process exit. Timeout errors preserve discovery and the live process.

### Fixed

- Table, CSV, and TSV columns include keys from every output row, so fields
  present only in later rows are no longer silently dropped. Missing cells stay
  empty; existing column order and CSV/TSV escaping are preserved.
- CLI tests without Ghidra cover reservation deletion and preservation of project
  files when Ghidra is unavailable; real project deletion runs in Ghidra integration tests.
- Windows import tests normalize Ghidra's `/C:/...` executable paths before
  comparing them with native filesystem paths.
- Project deletion holds the CLI lifecycle lock through removal and acquires
  Ghidra's project lock, refusing deletion while an external Ghidra owner is active.
- Stop, restart, and project deletion report final save failures and retain the
  JVM/program for recovery. Successful shutdown waits for accepted jobs and saving.
- Import rejects unsupported loader option names before loading or saving a program.
- Program metadata, status, operation responses, and artifact manifests use the
  saved project file name. `program info` and `summary` also expose its `path`;
  internal Ghidra names and original executable paths remain unchanged.
- Filesystem error details include `io_kind` even when a library wrapper hides
  the native error code. `os_error` remains null when that code is unavailable.
- Import applies `--program` to the actual saved file in every route and rejects
  an existing explicit name. Responses select the saved file, including automatic
  suffixes when no name was specified. One-shot imports confirm a structured save
  receipt and successful process exit before starting the persistent bridge.
- Startup and configuration I/O errors identify their operation and path. Import
  errors retain saved/analysis checkpoints and recovery arguments so a later
  bridge failure does not invite repeating an already saved import.
- Unsupported `memory write`/`memory search` fail with `patch bytes`/`find bytes`
  alternatives. Function rename rejects `--filter`/`--all`; ambiguous function
  names return candidates and require an address.
- GZF export ends and saves its transaction before packing, stages output beside
  the destination, and atomically replaces an existing file only on success.
- Fixed-width type aliases retain their widths across target ABIs. Type/field
  applicability, size, memory-range, and field-layout checks precede destructive
  edits. Type creation reports the actual registered name and path.
- Symbol edits revalidate selected IDs and metadata before changing any target;
  address selectors accept equivalent hex spellings while retaining address spaces.
- Byte patches validate their complete range before clearing code. Comments at
  interior addresses are readable, search rejects incomplete hex and treats glob
  punctuation literally, long raw-string results retain the match, and DOT output
  escapes identifiers and labels. Pcode work uses the active cancellation monitor.
- Configured output format is honored after explicit flags. Default limits apply
  after client filtering, sorting, and offset, except for counts or explicit zero.
  Batch query lines inherit the batch selection despite environment defaults.
- Compatibility restart preserves the actual selected program file path and
  propagates stop failures instead of starting a replacement JVM.
- Configuration updates use locked atomic replacement and preserve config
  symlinks. Setup validates private staging before publication, reuses valid
  installations, refuses incomplete existing destinations, and saves absolute paths.
- Job cancellation is isolated, completed history retains metadata only, and
  shutdown remains responsive with a full queue. Artifact hash failures return errors.
- CI unit coverage includes both library and binary targets.

## [0.4.0]

### Added

- `type set-field STRUCT --offset OFFSET` creates or updates a field's name,
  type, and comment without moving other fields. `type clear-field` leaves
  undefined bytes while preserving the structure size and later offsets.
  Results include before/after definitions, sizes, and whether anything changed.
- `type import-c --file PATH` and `--stdin` accept C definitions alongside the
  existing inline input, with exactly one source per invocation.
- Type expressions support fixed-length arrays, including pointer arrays and
  multidimensional arrays, using the target program's pointer width. Ambiguous
  short type names return full-path candidates instead of selecting a match.
- `batch FILE --on-error continue|stop` selects whether ordinary command errors
  allow subsequent lines to run. The default is `continue`; nested batches
  inherit the policy unless they override it. Completed edits are not rolled back.

### Changed

- Renamed the executable from `ghidra` to `ghidra-cli`, with no compatibility
  alias. Update command invocations in scripts and automation. Command examples
  below use the new executable name.
- Bridge discovery and startup locking now identify the project's `.rep`
  directory, so equivalent paths share one bridge, including directory aliases
  and Windows case variations on case-insensitive filesystems. Old discovery
  keys are not migrated: before upgrading from v0.3.0, stop each running project
  with the old executable (`ghidra stop --project P`), using the same project path
  used to start it. Start the bridges again after updating.
- Struct offsets accept decimal and `0x` hexadecimal. `add-field --offset`
  shares the new placement checks, rejecting interior offsets, overlaps with
  other defined fields, and packed layouts before editing the database.
  `type get` includes field comments, full type paths, generated display names,
  and the structure's packing status.
- Replaced `function set-var-type` with `function edit-var FUNCTION --var NAME
  [--name NEW_NAME] [--type TYPE]`. Rename and type changes share one request;
  either attribute can be changed alone. Results include the variable kind and
  before/after definitions. The old CLI and bridge command are removed.
- Batch failures now return nonzero status and retain successful results and
  structured error details. Save failures and timeouts stop subsequent commands;
  timeouts retain exit code 75.
- Program edits, analysis, and scripts now save automatically before reporting
  success. `program save` retries pending saves without restarting the bridge;
  save failures return an error with the original command result. Failed or
  cancelled operations can retain partial changes, which are also saved.
  Switching or closing a program saves first and keeps it open if saving fails.
  Saving a stopped bridge remains a no-op.
- Local, setup, and bridge-management commands now follow the shared output
  defaults: human-readable on TTY and compact JSON on non-TTY. `--json` selects
  compact JSON, `--pretty` selects indented JSON, and an explicit output format
  takes precedence. Progress and verbose diagnostics go to stderr; JSON-mode
  errors include `status`, `message`, `exit_code`, and available bridge details.
  Argument errors retain exit code 2, command failures 1, and timeouts 75.
- CLI help lists supported query types, output formats, and `set-default` choices;
  invalid choices fail during argument parsing before bridge startup.
- Split Rust CLI definitions by command family, isolated guarded symbol edits
  and script preparation, and separated bridge startup from discovery/liveness.
  Integration tests are organized by behavior domain, with new routing and
  target-layout memory coverage in CI. Local CLI suites no longer require Ghidra;
  Ghidra-dependent suites still fail when prerequisites are unavailable.

### Fixed

- Batch commands preserve quoted arguments, empty strings, escapes, and trailing
  escaped whitespace without evaluating shell syntax. Malformed quoting is
  reported for the affected line. Each line honors its project/program targets
  and query options through the same routing as standalone commands.
- List commands fetch all required rows before client-side filtering, sorting,
  counting, and pagination. Field selection now runs after sorting and pagination,
  so omitting a sort field from `--fields` no longer changes the selected rows.
- Filters reject incomplete expressions and trailing input, honor `NOT`/`AND`/`OR`
  precedence and parentheses, and correctly evaluate existence checks, `IN`,
  nested fields, and quoted values. Integer and address comparisons preserve all
  bits instead of rounding through floating point.
- CSV and TSV correctly escape delimiters, quotes, and embedded newlines.
  Compact output truncates strings at UTF-8 boundaries; NDJSON and other framed
  output no longer gain an extra blank line. Closed output pipes no longer panic
  or turn completed operations into failures.
- `doctor` returns a nonzero status when readiness checks fail, including in JSON
  mode. Handler diagnostics survive bridge error conversion, including failed
  scripts' captured stdout, artifact checks, and partial-save details.
- Bridge connection attempts and retry backoff obey one overall deadline. Socket
  timeout setup failures are reported before sending a request. An unexpected
  EOF reports that the command outcome is unknown and directs callers to inspect
  state before repeating edits.
- `program delete` can delete the initial/current program and closed programs
  without selecting the deletion target. Deleting another program preserves the
  current selection; save failures and other consumers prevent unsafe deletion.
  Stopped bridges, empty projects, and batch deletion use the same ownership rules.
- Project management and imports share artifact and persisted-data checks,
  preserve dotted project names, and resolve relative project paths consistently.
  `--projects-dir` and `GHIDRA_INSTALL_DIR` overrides apply to management, doctor,
  and execution. Project listing returns actual project names; deletion removes
  `.gpr`/`.rep` artifacts while preserving a nonempty same-named directory.
- Import, export, and patch-export paths resolve relative to the CLI's working
  directory, including when a bridge was started elsewhere. JDK detection follows
  executable symlinks while keeping `JAVA_HOME` usable by Windows launchers.
- `memory read` decodes pointers using the target program's pointer width, byte
  order, and address spaces. Function-pointer detection handles high addresses,
  overlays, and partial reads instead of assuming 64-bit little-endian pointers
  within a fixed address range.
- `graph callers` and `graph callees` traverse by shortest distance so a longer
  path cannot hide nodes reachable within the depth limit through a shortcut.
  Traversal retains reference rows, result limits, and cancellation checks.
- `function set-signature` checks Ghidra's application result and reports its
  diagnostic when a parsed signature cannot be applied, instead of returning
  success. Decompilation, high PCode, variable inspection, and program diff
  initialize decompiler options explicitly.
- `patch bytes` validates complete hexadecimal byte pairs before editing memory;
  `patch nop` rejects non-x86 processors. Program and patch exports report file
  write failures, exporter rejection, and underlying reflective errors.
- Test fixtures prefer exact function names before decorated-name fallbacks and
  honor installation overrides. Windows lifecycle output capture and test path
  handling no longer hang or misinterpret separators, spaces, or apostrophes.

## [0.3.0]

Changes since upstream 0.2.2 ([`10019ba`](https://github.com/toratako/ghidra-cli/commit/10019ba1f3b54c9edcca8ec644a30e16fb7b7c79)),
including the electricazimuth integration in
[`a6a4103`](https://github.com/toratako/ghidra-cli/commit/a6a4103e0bd358d1c7146151f7e8f9e9f617830d),
selected nonsleepr and encounter changes, and subsequent work in this repository.

### Added

- `ghidra-cli pcode at ADDRESS` and `pcode function TARGET [--high]` expose raw
  instruction PCode and decompiler high PCode, including operands, outputs,
  address spaces, and register names.
- `ghidra-cli analyzer list|set|run` lists analyzer settings, enables or disables a
  named analyzer, and explicitly re-runs analysis. Changing a setting with
  `analyzer set NAME true|false` does not itself start analysis.
- `ghidra-cli type import-c CODE [--category PATH]` (aliases `type import` and
  `type parse-c`) parses C declarations, including structs, unions, enums,
  typedefs, and function definitions. Results include type names, paths, sizes,
  categories, and parser messages. Category placement applies to the parsed
  types without moving unrelated existing types with the same name.
- Explicit import controls: `--loader`, `--language` (alias `--processor`),
  `--compiler-spec` (alias `--cspec`), and repeatable
  `--loader-option NAME=VALUE`. Raw binary options `--base-address`,
  `--block-name`, `--file-offset`, and `--length` imply `BinaryLoader` when no
  loader is specified. Explicit loader imports stop any running project bridge,
  import through `analyzeHeadless`, and reopen the imported program.
- `ghidra-cli disasm-at ADDRESS [--count N]` creates instructions at an unanalyzed
  address and reports both Ghidra's `ok` result and whether an instruction
  actually `landed` at the target.
- `ghidra-cli clear START:END [--to-data | --disasm-at ADDRESS]` clears overlapping
  code units, optionally re-disassembling at a specified address in the same
  request.
- `ghidra-cli function set-noreturn TARGET [--value true|false]` controls a
  function's no-return flag. `function get` and `function list` now include
  `no_return`.
- Function-scoped tag commands: `function tag add|remove TARGET TAG_NAME` and
  `function tag list TARGET`, complementing the top-level `tag` commands and
  function tag filters introduced in 0.2.2.
- `ghidra-cli script run -` reads Java source from stdin and stages it for the same
  compilation and execution path used by script files.
- `ghidra-cli comment set ADDRESS --stdin` and `--text-file PATH` accept comment
  text without exposing it to shell argument expansion.
- `ghidra-cli type apply ADDRESS TYPE --force` (alias `--clear-conflicting`) clears
  overlapping instructions or data before applying a type. Replacing a function
  entry point reports a warning that its code was cleared.
- `ghidra-cli program save` flushes pending edits by stopping the bridge, reopening
  the same program, and checking its function count. This works around the
  headless harness's lifetime transaction, which prevents an in-place save.

### Changed

- Temporarily paused macOS CI jobs and release builds while decompiler and
  fixture symbol failures are investigated. CI and release binaries now target
  Linux and Windows.
- Updated the GitHub Release action and use the tagged version's changelog
  section as release notes. crates.io publishing requires the repository
  variable `PUBLISH_CRATES_IO=true` and a configured `CARGO_REGISTRY_TOKEN`.
- `function create ADDRESS [NAME]` attempts disassembly first when the target
  has no instruction.
- `find calls TARGET` now returns calls made by the target function, scanning
  its entire body. Rows use `call_site`, `callee`, `callee_address`, and `type`
  instead of the previous incoming-call `address`/`caller` fields.
- `patch nop --count N` stops at the first missing instruction after a
  successful patch and reports the actual count and patched instructions.
  A missing instruction at the starting address still fails; reaching a gap
  later no longer rolls back the preceding patches.
- Separated Rust CLI workflows, bridge transport, headless import, and bridge
  diagnostics into dedicated modules. Split the Java bridge into runtime,
  scheduling, program-session, and command components; startup and `doctor`
  compile the same complete source bundle. Handlers resolve the current
  program and per-job monitor through the shared session.
- Rust library APIs now carry import/export limits in
  `BridgeClient::list_imports`/`list_exports` and analysis/loader settings in
  `bridge::import_oneshot` via `OneShotImportOptions`.
- `cargo test-run` shares a closed, analyzed fixture across test executables
  within one invocation, giving each suite an independent project copy.
  Fixture creation uses file locks and atomic publication; setup failures are
  cached for that run. Prerequisite checks run once per suite, and fixture
  import avoids starting a throwaway bridge. Plain `cargo test` retains a
  fixture local to each test executable.
- Integration tests build a host-native fixture from Rust source, use isolated
  temporary projects, and derive test addresses from the imported program.
  CI no longer reuses mutable Ghidra project caches. Integration jobs use
  `cargo test-run`, include tag and fixture coverage, and release validation
  runs the full test set. Added regression coverage for cancellation followed
  by another job, program switching, and persistence after a failed mutation.
- Reorganized agent guidance under `docs/skills/SKILL.md`, with runtime and
  recovery guidance in `docs/runtime.md` and implementation documentation beside
  its modules. Replaced the old `.claude`-specific guidance and separated future
  plans from the command reference.
- Updated Cargo dependencies and adapted output formatting, hashing, HTTP/TLS,
  and ZIP extraction to their current APIs.
- Package metadata now points to `toratako/ghidra-cli` and lists `toratako`
  alongside original author Alexander Kiselev. Recorded incorporated upstream
  contributions in `LICENSE`.

### Fixed

- Fresh imports no longer run auto-analysis twice. `import --no-analyze` now
  also disables analysis in the one-shot importer; imports through an existing
  bridge still run analysis when requested.
- Failed headless imports include recent stdout and stderr in their
  diagnostics, including errors that Ghidra reports on stdout.
- Program switching resolves the project's file path rather than comparing
  internal program names. `--program`, `program open`, `analyze`, and the
  current-program marker now distinguish copied programs with identical names,
  including files in project subfolders.
- Failed nested mutation transactions no longer roll back earlier successful
  commands in the headless session. Partial changes from the failed request can
  remain; this does not provide atomic rollback per request. Standalone
  transactions retain commit/rollback behavior.
- Clean bridge shutdown persists pending edits. `program close` now reports
  that closing did not save them to disk; use `program save` or `stop` to flush
  edits before closing.
- Java scripts load from the exact OSGi bundle registered for their directory,
  preventing broader registered script paths from shadowing it. Removed a
  reflective class-name literal that made the OSGi analyzer add an unwireable
  package import and break bridge startup.
- `symbol rename`, top-level `rename`, and `symbol delete` reject ambiguous
  names unless scoped with `--address`/`--filter` or explicitly applied to all
  matches with `--all`. `symbol delete --filter` now scopes the deletion.
  `function rename OLD NEW --address ADDRESS` honors the exact entry address
  and rejects an `OLD` name mismatch.
- `type create` rejects C declarations and other non-identifier names instead
  of silently creating an empty struct named after the entire input. Use
  `type import-c` for declarations or `type add-field` to populate an empty struct.
- `function create` and `type apply` errors include structured details about
  owning functions, missing instructions, overlapping code units, and conflicting
  data types/ranges. Error detail is printed as JSON on stderr with `-vv` or
  `--json`.
- Address-field filters accept quoted hexadecimal values with or without a
  `0x`/`0X` prefix. `memory read` and patch operations resolve overlay-qualified
  addresses; `clear` parses ranges such as `rom1::5512:551d` and inherits the
  start address's space for an unqualified end address.
- `xref to` resolves external import names and their local thunk targets,
  collecting references to all matching addresses without duplicate rows.
- `strings refs PATTERN` searches matching defined string values and returns
  their references instead of treating the pattern as an address.
- `graph callers` recognizes parameter and indirection references as well as
  direct calls. `graph callers`/`callees` honor `--limit` during recursive
  traversal, avoiding an exhaustive walk before truncating the output;
  `--limit 0` remains unlimited.
- `dump imports|exports` and `query imports|exports` pass row limits to the
  bridge, including the unlimited `--limit 0` case.
- `patch bytes` and `patch nop` temporarily enable writes to read-only memory
  blocks and restore the original permission afterward.
- `analyzer set NAME true|false` accepts an explicit boolean and displays
  `--help` without panicking. Missing or invalid values produce argument errors.
- Socket read timeouts report `Timeout:` with exit code 75 (`EX_TEMPFAIL`),
  distinct from bridge failures with exit code 1. A client timeout does not
  cancel the server-side job; inspect `ghidra-cli jobs` before retrying.

### Removed

- The legacy `type` argument alias for the bridge's `comment_set` request.
  Direct protocol clients must send `comment_type`; the CLI continues to expose
  `--comment-type`.

## [0.2.2]

### Added

- **Function tags** (#17) — expose Ghidra's `FunctionTagManager` for organizing
  large codebases: `ghidra-cli tag list|get|create|delete|rename|set-comment|add|remove`,
  plus `ghidra-cli function list --tag NAME` (repeatable, AND semantics, filtered
  server-side) and `--untagged`. `tag add` auto-creates missing tags (strict mode
  via `--no-create`) and reports `added`/`created`/`already_present`; `tag
  remove` is likewise idempotent. `tag delete` reports both Ghidra's raw
  `use_count` and the non-external `functions_affected`. Unknown-tag lookups
  error with a `Did you mean ...?` hint instead of returning empty results.
  Function rows (`function list`/`get`) now carry a sorted `tags` array.
- `--filter` expressions now work on array-valued fields (e.g. `tags`,
  `operands`) with any-element semantics: `tags ~ 'crypto'` matches if any
  element matches; `tags != 'x'` means NO element equals `x`. Previously such
  filters silently matched nothing.
- Responsive `ping`, `status`, `bridge_info`, `jobs`, and `cancel` use snapshots
  independently of the single Ghidra program lane. Program requests receive job
  IDs and wait in a bounded FIFO (256), replacing the invisible socket backlog.
- `ghidra-cli jobs [JOB_ID]` — inspect the active job, the queue, and recent history
  (the bridge keeps the last 100 jobs), or one job by ID.
- `ghidra-cli cancel [JOB_ID]` — cooperatively cancel the active job (or a specific
  one). A job that hasn't started is dropped from the queue immediately; a running
  job is cancelled via a per-job `TaskMonitor`.

### Changed

- CSV output joins array-valued cells with `;` instead of `, ` — a `, `-joined
  array inside an unquoted CSV field shifted every subsequent column (affects
  the new `tags` column plus existing in-row arrays like `operands`/`params`).
- `function list` rows gained a `tags` column, changing CSV/table headers for
  existing consumers.
- `BridgeClient::list_functions` grew `tags`/`untagged` parameters.
- `ghidra-cli script run` runs a checked-in script by absolute path with real
  positional arguments (everything after `--`) and captured stdout, returning
  `{script, path, stdout, args}`. New `--expect PATH[:MIN_ROWS]` (repeatable) fails
  the job when an output artifact is missing, empty, or short; `--allow-empty`
  permits an expected-but-empty file. Scripts run on the cancellable job lane, so
  `ghidra-cli cancel` works on them.

### Fixed

- Commands issued while the bridge is busy now wait in the queue instead of
  failing with "bridge not responding" — a slow analysis no longer looks like a
  dead bridge.
- Import now treats stale empty `.gpr`/`.rep` project artifacts as uninitialized
  and uses the durable one-shot import path instead of trying to start a
  project-mode bridge that Ghidra rejects because it contains no programs.
- Removed the inert legacy config key `timeout`. Old YAML files containing it
  still load, but the key is dropped when saved and `config set timeout` points
  to the active read, long-operation, connection, and launch timeout controls.
- `patch nop --count N` now NOPs N consecutive instructions (was: silently
  ignored, only the instruction at the address was patched). The client forwards
  the count and the bridge walks instruction by instruction, so variable-length
  ISAs work; if any address in the run has no instruction the whole patch rolls
  back.
- `comment set --comment-type PRE|POST|PLATE` now takes effect (was: always
  `EOL`). The client sent the type under key `type` while the bridge read
  `comment_type`; the client now sends `comment_type` and the bridge still
  accepts the old key as a fallback.

## [0.2.1]

### Fixed

- `--limit 0` now means all rows in both client pagination and bridge requests,
  fixing empty exports and accidental fallback to the 1000-row default.
- **Malformed `--filter` expressions now fail with a clear error** (was:
  the parse error was swallowed and the CLI dumped the *entire unfiltered,
  unlimited* dataset while exiting 0). A bare word like `--filter PK` is
  rejected up front — before any bridge fetch — with a hint to use
  `name~PK` (contains) or `name=~"^PK_"` (regex). The filter DSL is now
  summarized in `--help` for `--filter` and `--limit`.
- **`=~` regex filters are now case-insensitive**, matching the other string
  operators. Field values are lowercased before matching, so an uppercase
  pattern like `name=~"^PK_"` previously matched nothing, silently.
- Filter regexes are compiled once per pattern instead of once per row,
  removing a large constant cost when filtering datasets with millions of
  rows (e.g. 1.9M symbols).

## [0.2.0]

### Added

- **Automatic full-JDK detection for Ghidra.** Ghidra compiles its bridge script
  at runtime and needs the `jdk.compiler` module, so a JRE (or a `jlink`-trimmed
  image) silently fails. ghidra-cli now resolves a suitable JDK itself —
  requiring `javac`, the `jdk.compiler` module, and major version ≥ Ghidra's
  minimum (21 for Ghidra 12.x) — and hands it to `analyzeHeadless` via
  `JAVA_HOME` rather than relying on Ghidra's PATH-based pick. Override with the
  `--java-home <PATH>` global flag, `java_home` config, or `GHIDRA_CLI_JAVA_HOME`.
- Global `--project` / `--program` flags — usable before any subcommand
  (e.g. `ghidra-cli --project P --program bin function list`); previously these were
  accepted only per-subcommand.
- Global `--projects-dir <DIR>` flag (with `ghidra_project_dir` config and
  `GHIDRA_PROJECT_DIR` env) to choose where Ghidra projects are stored.
- `ghidra-cli import --no-analyze` — import a binary without running auto-analysis
  (the program is still persisted).
- `ghidra-cli program export` now supports the built-in Ghidra exporters in addition
  to JSON: `xml`, `c`/`cpp`, `binary`/`bin`, `gzf`, `ascii`/`asm`, `hex`, and
  `html`. Exporters are resolved by class name and 4-arg arity so they keep
  working across Ghidra versions.
- Config `launch_timeout_secs` (env `GHIDRA_CLI_LAUNCH_TIMEOUT`, default 180s) —
  bounded cap for bridge launch readiness. Env `GHIDRA_CLI_OP_TIMEOUT` caps the
  otherwise-unbounded long-running TCP ops (`analyze` / `import`).

### Changed

- `ghidra-cli import` now runs auto-analysis by default (over TCP) and reports the
  resulting `function_count`. Use `--no-analyze` to skip it.
- `ghidra-cli doctor` and `ghidra-cli setup` now require and verify a **full JDK** (not
  just any Java on `PATH`): `doctor` reports the selected JDK and compiles the
  embedded bridge script as a real health check, surfacing the actual error on
  failure.
- The `ilspy-cli` companion tool was extracted into its own repository and is no
  longer part of this workspace.

### Fixed

- **`ghidra-cli import` no longer hangs on non-trivial binaries.** The bridge now
  launches via `-preScript -noanalysis` (was `-postScript` with full analysis),
  so its TCP socket binds right after the binary loads — before analysis — and
  readiness is fast. Analysis runs afterwards as an unbounded TCP `analyze`
  operation (which also persists the program via `analyzeAll` + `save`),
  decoupling a **bounded launch** (JVM start + OSGi compile + load, capped by
  `launch_timeout_secs`) from **unbounded analysis**.
- Bridge launch/teardown can no longer hang or orphan a JVM. The JVM tree is
  spawned in its own process group and a launch failure/timeout kills the whole
  group (`killpg` on unix, `taskkill /T` on windows) **before** joining the
  output reader threads. Previously the readiness wait capped at 120s while
  analysis kept running, then killed only the `analyzeHeadless` wrapper (not the
  JVM grandchild) and blocked forever joining pipes the surviving JVM held open.
- `ghidra-cli stop` now force-kills the whole bridge process group as a fallback,
  not just the JVM PID.
- `ghidra-cli program close`, `program delete`, and `program export` now work — the
  Rust client was sending command names (`close_program`, `delete_program`,
  `export_program`) the Java bridge never registered, so they always errored.
- `--filter`, `--sort`, `--count`, and `--offset` are now honored on all list
  commands (`function list`, `strings list`, `symbol list`, `type list`,
  `query`, `dump`). The bridge only does a literal substring match on the name
  field, so ghidra-cli now fetches the full dataset and applies the real filter
  DSL, sort, pagination, and count client-side.
- Call-graph and callee traversal now find every call within a function body,
  not just calls at its entry point (the reference scan now iterates all
  reference sources in the function body).
- `program export --format binary` and the other native exporters no longer fail
  on Ghidra 12: the `Exporter.export` method is resolved by name + 4-arg arity
  rather than an exact `Program.class` signature that drifted across versions.
- Default project directory no longer breaks on Linux with Ghidra 12.1+, which
  rejects any project location containing a dot-prefixed path component
  (e.g. `~/.cache`). The default now falls back to `~/ghidra-cli-projects` when
  the cache path has a hidden component (macOS/Windows keep their cache-dir
  location).
- `ghidra-cli project delete` now actually deletes the project. It removes the
  Ghidra `<name>.gpr` / `<name>.rep` artifacts (previously it looked for a
  non-existent `<name>` directory and silently deleted nothing) and stops any
  running bridge first so the project lock is released. `ghidra-cli project info`
  likewise reports `Exists` based on those artifacts.

[unreleased]: https://github.com/toratako/ghidra-cli/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/toratako/ghidra-cli/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/toratako/ghidra-cli/compare/10019ba1f3b54c9edcca8ec644a30e16fb7b7c79...v0.3.0
[0.2.2]: https://github.com/toratako/ghidra-cli/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/toratako/ghidra-cli/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/toratako/ghidra-cli/releases/tag/v0.2.0
