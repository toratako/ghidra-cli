# Changelog

Release history follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Unify normal JSON as `data` with optional nonempty `meta`, including management
  commands and batch reports. Standalone results and batch entries now match;
  lists retain context and effective paging metadata through field projection.
  Classify result shapes by command, keeping single objects and graphs intact.
- Emit every NDJSON list as one value per line, including project lists; empty
  lists emit no lines. Count results remain unwrapped numbers in NDJSON.
- Restrict `function get`, `type get`, and `decompile` to single-result output
  controls. Keep `symbol delete` target filtering and field projection, removing
  list sorting, paging, and counting from its receipt. Count comments by row in
  `comment get` and retain the target address as list context.

## [0.7.0] - 2026-09-22

This stable release includes all changes from
[0.7.0-rc.1](https://github.com/toratako/ghidra-cli/releases/tag/v0.7.0-rc.1)
plus the changes below.

### Added

- Detect Ghidra through PATH and known Linux/macOS package layouts when no
  installation is configured. Report the selected path, source, and version in
  doctor, and report ambiguous installations with their candidate paths.

### Changed

- Validate explicit Ghidra paths and reject empty installation overrides without
  falling back. Share installation validation with setup and preserve detection
  diagnostics through command dispatch.

- Group instruction definition and range clearing under `listing define-code`
  and `listing undefine START --end END`. Undefine requires an inclusive end
  address; each endpoint is specified independently. Remove the top-level
  `define-code` and `clear` commands.

## [0.7.0-rc.1] - 2026-09-21

### Added

- Add `batch --from-line N` to resume an edited source file without replaying
  earlier commands, with structured recovery guidance for rolled-back failures,
  uncertain outcomes, and pending saves. Lost or malformed bridge responses now
  stop batches even under `--on-error continue`.
- Add `function get --with-signature` for Program-defined return/parameter types,
  storage, automatic arguments, indirect types, and thunk signature provenance.
- Add `function set-stack-purge TARGET --bytes N | --unknown` and expose
  known, unknown, and invalid stack-purge states in function queries.
- Add `data list` and bounded `data read TARGET` for applied data types and
  their values, including structures, arrays, pointers, and interior components.
- Add `memory read --source original` for preserved import bytes and file
  provenance in `memory info`; current-memory reads remain the default.
- Add `bookmark list/get` for analysis diagnostics and user notes, and
  `memory info TARGET` for listing state and containing object boundaries.
- Add `program list-relocations` with native relocation evidence and
  `function list-calling-conventions` with the selected program's default.
- Expose disjoint body ranges in `function get`, operand/source/primary metadata
  in xrefs, original executable hashes in `program info`, and component ordinals
  and bitfield layout in `type get`.
- Add decompiler basic-block counts and `decompile --with-jump-tables` for
  recovered case destinations and default branches.
- Add structured decompilation warnings with their source, message, and available
  address. Successful decompilation remains successful when warnings are present.
- Add `is_external` and `entry_memory` to function queries and decompilation,
  using the memory map's block names and permissions.
- Add `analysis option list/get/set` for typed Program analysis settings,
  including analyzer enablement, nested options, defaults and enum choices.
  Setting values saves without running analysis.
- Add `type create union` and union member addition, deletion, and editing through
  `type field append`, `type field delete`, and `type field set --ordinal`.
- Add `type enum member delete TYPE --name MEMBER` to remove one named enum member.
- Add `find constant VALUE` and inclusive `--min`/`--max` searches over numeric
  instruction operands, with optional bit-width and address bounds.
- Attach versioned skill ZIP archives to GitHub releases, including each skill's
  `SKILL.md` and supporting references.
- Add Gitleaks pre-commit configuration and hook definitions for secret scanning.

### Changed

- Validate all selected batch commands and their nested batches before execution,
  retaining the checked input for execution. Syntax errors report all locations
  and execute no commands; `--on-error` controls execution-time failures.
- Include actual artifact paths and sizes, exporter messages, and format
  limitations in `program export` results.
- Group field operations under `type field append/set/clear/delete` and enum
  member deletion under `type enum member delete`. Select existing fields with
  `--field NAME`, struct `--offset`, or union `--ordinal`; `--name` sets a field's
  new name. Struct deletion now accepts an exact starting offset, including for
  unnamed fields. Named struct bit-field and zero-length field deletion remains
  available; clear still preserves structure size and later offsets.
- Return a common struct/union field receipt with canonical type identity,
  `changed`, containing-type sizes, and component snapshots in `before`/`after`.
  Appending reports `appended`; set, clear, and delete retain distinct actions.
- Move binary import to `program import` and use `--name` for the saved program
  name. Import still creates projects as needed and runs analysis by default.
- Replace top-level `analyze` with `analysis run` and remove `analyzer list/set`
  in favor of `analysis option`. Analysis runs with saved Program settings.
- Reuse the native decompiler across decompile, high P-code and variable edits
  while the selected Program is unchanged. Reopen after Program changes and
  release it on decompilation failure, cancellation, Program switch or close.
- Make `xref from TARGET` inspect one source address; `--function` explicitly
  selects the whole containing function. Disassembly no longer rewinds from an
  undefined address to the containing function's entry.
- Require `comment delete` to select `--comment-type` or `--all`, preserving
  other comment types for a selective deletion. Both `comment set` and
  `comment delete` reject unsupported comment types before mutation.
- Rename label creation to `symbol create-label`, external-symbol listing to
  `symbol externals`, and external-entry-point listing to `symbol entry-points`.
  Rename their bridge adapters and result collections to match.
- Clarify `string refs PATTERN` as case-insensitive substring search followed by
  reference lookup; its bridge argument is `pattern`.
- Rename setup's Java prerequisite bypass to `--skip-java-check`.
- Make `tag get NAME` return tag details (`name`, `comment`, `use_count`). Use
  `function list --tag NAME` for member functions. `tag get` retains target and
  output options; filtering, sorting, pagination, and count options are removed.
- Consolidate call queries under `graph callers` and `graph callees`; remove
  `find calls`, `function calls`, and their bridge/client adapters. All call
  graphs share instruction validation and thunk/typed-pointer resolution.
  Traversal rows now contain both endpoints, call site, original reference
  destination/type, and depth in a common `calls` array. Keep undefined endpoints
  and calls into function interiors; only recursive expansion needs a function.
  Whole-program graph edges carry the same call details alongside `from`/`to`.
- Make `type field append` append-only. Use `type field set --offset` for creating
  or updating a field at a specific position. `field set` now accepts `--size`
  with `--type`, preserving explicit-length field placement and returning
  created/updated/unchanged receipts with before/after definitions.
- Ordinary single-program commands now commit only on success and roll back the
  current request on failure or cancellation. This includes C type import,
  function/variable edits, memory writes, clear plus disassembly, and multi-symbol
  deletion. Earlier successful commands remain saved. Errors identify completed
  rollback with `detail.rolled_back`; failed deletion receipts report
  `attempted_deleted`, not committed deletions. Analysis, arbitrary scripts,
  import/export, and program lifecycle operations retain separate partial-effect
  semantics; `batch` remains a sequence of independently saved commands and stops
  on transaction-boundary failures regardless of `--on-error`.
- Require the running bridge to advertise `atomic_edits` before program command
  dispatch. Unsupported bridges require explicit restart, without an automatic
  upgrade script. `program save` remains available directly for recovery before
  restart. Human-readable errors explain rollback and retained partial changes.
- Dispatch bridge commands once, removing automatic bridge restarts and command
  replay after unsupported-command errors or stale response shapes.
- Replace `length` in `string list` and `find string` rows with `char_length`
  (Unicode code points in the decoded value) and `byte_length` (occupied Ghidra
  data bytes, including terminators/padding when defined). Update filters,
  sorting and field selections to use the explicit unit. Both commands now
  share string scanning and row generation; their response envelopes are unchanged.
- Apply `find string` paging in the bridge when the query permits it, after
  matching both the search pattern and any supported `value~...` filter.
  Sorting, counts and unsupported filters retain complete-input processing.
- Restore macOS release binaries for Intel and Apple Silicon, with macOS ARM64
  included in the full test suite that gates release artifacts.
- Mark GitHub releases from prerelease version tags as prereleases.
- Skip Ghidra integration CI for Markdown-only changes while retaining unit and
  CLI checks. Run infrastructure suites in separate daemon and project jobs;
  documentation pushes no longer cancel running Ghidra tests for code changes.

### Removed

- Remove `--filter`, `--sort`, `--offset`, `--limit`, and `--count` from
  `memory read`, `program info`, and `program stats`. These commands return a
  single object and retain target selection, `--fields`, and output formats.
  `memory read ADDRESS SIZE` still specifies the requested byte count with `SIZE`.
- Remove the remaining `--target` options from function edits and queries,
  `decompile`, `disassemble`, `xref to/from`, and `graph callers/callees`.
  Pass one required positional `TARGET` instead.
  Supplying `--target` now fails during argument parsing instead of silently
  overriding a positional target, including in batch commands.
- Remove address-only symbol rename/delete bridge requests and their Rust client
  adapters. Requests now require complete `targets` snapshots, revalidated by
  stable symbol ID before mutation.
- Remove the fire-and-forget bridge `shutdown` command and the `name` fallback
  for `type_create`. Direct clients use `shutdown_wait` to confirm the final save
  and `definition` for struct creation.

### Fixed

- Preserve boolean, numeric, and null `value` fields in compact text output,
  including typed analysis option values displayed beside their names.
- Reject unknown bridge response statuses instead of treating their payloads as
  successful results. Transport failures after sending starts, malformed replies,
  and read timeouts expose `detail.outcome_unknown` in structured diagnostics;
  commands may already have taken effect. Read timeouts retain exit code 75 and
  do not cancel the server job.
- Preserve inferred parameters when setting a function's return type, keeping
  their types inferable where the calling convention permits and rejecting
  conflicts instead of silently renaming existing symbols.
- Reject calling convention names unsupported by the selected program's compiler
  specification before changing the function.
- Fix the macOS doctor loopback check by restoring blocking mode on the accepted
  socket, and restore macOS ARM64 CI with native Ghidra tools and portable fixtures.
- Preserve references from distinct operands to the same destination in `xref to`.
- Report Ghidra diagnostics instead of inferring .NET code from bad-instruction
  output. C-only output sends diagnostics absent from its comments to stderr.
- Accept adjacent pointer return declarators such as `Entry *lookup(...)` in
  `function set-signature`, preserving the pointee and pointer depth. Reject C
  type qualifiers that Ghidra function signatures cannot preserve with an
  explicit diagnostic, leaving the function unchanged.
- Describe `script list` as listing `.java` and `.py` files in Ghidra's script
  directories without checking whether they can be executed.
- Preserve applied data types and settings during `memory write`, changing only
  differing bytes and clearing only affected instructions without redisassembly.
  Update identifiable automatic pointer references while retaining explicit
  references. Reject edits that change string storage lengths, affect unsupported
  dynamic layouts, or modify shared byte/bit-mapped memory.
- Preserve the first save failure across every request lifecycle path, without
  an implicit second save at request completion. Pending edits remain available
  for `program save`; a failed later atomic edit does not save or discard them.
- Keep previews from committing preceding request edits, restore request state
  after transaction-start failure, and detect unclosed native transactions
  without ending another owner's transaction or reporting an incomplete rollback
  as successful.
- Treat C parser lexical errors as failed imports so partially parsed definitions
  are rolled back rather than leaving the request transaction open.
- Require `program export --output` during argument parsing for all export formats,
  rejecting omitted destinations before connecting to Ghidra.

## [0.6.1] - 2026-09-21

### Fixed

- Preserve file modification times when installing Ghidra from its ZIP archive,
  keeping compiled language definitions newer than their sources and avoiding
  unnecessary recompilation during parallel imports. CI installation caches are
  refreshed; existing installations can be recreated in a new `setup --dir`.

## [0.6.0] - 2026-09-21

### Added

- `find bytes --regex PATTERN` searches memory with Ghidra's native byte regex
  engine and returns match addresses and byte lengths. It supports shared query
  options and cancellation, preserves literal hex search, and rejects invalid
  patterns and encountered zero-length matches.
- `find text TEXT --encoding CHARSET` searches program memory for exact encoded
  text regardless of string definitions. UTF-8 is the default; results include
  match addresses, byte lengths, and encoding names. Unrepresentable text is
  rejected, and searches support shared query options and cancellation.
- `define-code TARGET [--end END]` defines instructions by following code flow,
  optionally restricted to an inclusive range in one address space. Only complete
  instructions and delay-slot groups inside the range are created; existing code
  and data are preserved. It saves changes and returns a receipt; use `disassemble`
  to read the resulting instructions.
- Generated [command tree](docs/tree.md), with `cargo xtask gen-tree` to update it
  and `cargo xtask gen-tree --check` to detect stale documentation in CI.

### Fixed

- Resolve native program exporter classes through Ghidra's exporter class loader,
  fixing class-loading failures in the bridge's OSGi bundle.
- Refuse `program delete` for non-Program files, preserving project data type archives.
- Return decompiler parameters in declaration order. Apply the configured native
  decompiler timeout to high p-code and variable edits as well as `decompile`;
  reject invalid budgets instead of silently making them unlimited.
- Match actual string values in `string refs`, including backslashes, quotes and
  newlines, independently of the JVM locale.
- Include external and unmapped-address comments in `comment list`, and resolve
  default thunk and dynamic-label names consistently with `symbol list`.
- Reject overflowing query limits and graph depths instead of narrowing them to
  unrelated values in the Java bridge.
- Load package-declared Java scripts from files and stdin by their qualified class names.
- Recognize Thumb function pointers in memory annotations while preserving raw values.
- Preserve explicit `signed char` signedness on unsigned-char ABIs, reject type
  renames that Ghidra cannot apply, and delete registered array and pointer types
  using their stored identities.
- Preserve the supplied input filename as the default saved program name when
  importing through a symlink, including both one-shot and running-bridge imports.
- Apply `graph calls` filters, sorting, pagination, field selection, and counts
  to function nodes while preserving the graph structure and outgoing edges.
- Preserve component settings on unrelated structure fields during offset edits,
  and on the edited field when only its name or comment changes.
- Exclude non-Program project files from `program list` and `bridge status` program counts.
- Show requested decompiler parameters and variables in compact text output.
- Reject overflowing `--expect` minimum row counts instead of silently dropping
  the constraint; validate bridge row-count arguments before running scripts.

### Changed

- Breaking: group type creation under `type create struct NAME`,
  `type create enum NAME --values ...`, and `type create typedef NAME BASE`.
  The former `type create NAME`, `type create-enum`, and `type typedef` forms
  are no longer accepted; creation behavior and `type import-c` are unchanged.
- Rename `x-ref` to `xref`, `strings` to `string`, `disasm` (including
  `function disasm`) to `disassemble`, and `clear --disasm-at` to
  `clear --disassemble-at`. The `string` namespace retains `list` and
  `refs`. Use `ndjson` instead of `json-stream` for `--format` and configured
  output formats. Previous spellings are no longer accepted.
- Remove all command aliases. Use the canonical command names shown in help.
  Import accepts `--language` and `--compiler-spec`, replacing `--processor` and
  `--cspec`; `type apply --force` replaces `--clear-conflicting`.
- Breaking: address inputs now require explicit `0x`/`0X` components, including
  qualified (`overlay:0x1000`) and segmented (`ram:0x1234:0x0005`) addresses.
  Unprefixed targets such as `add`, `dead`, `401000`, and `FUN_00401000` are
  exact names only; missing or malformed targets never fall back to inferred
  addresses. Address output uses the same reusable syntax and preserves spaces;
  segmented output always includes the space name to avoid ambiguous parsing.
  `clear START:END` requires explicit endpoints and rejects the legacy `::`
  spelling; offsets, counts, and raw byte patterns retain their numeric rules.
- Address comparisons and membership tests in query filters also require explicit
  address literals. Validation runs before row evaluation, preserves address spaces
  and segments, and compares full 64-bit values without losing precision.
- `disassemble` uses the shared `--limit` after filtering, sorting, and offset,
  replacing `--instructions` and the implicit ten-instruction cap. Omitted limits
  use `default_limit`; `--limit 0` is unlimited. The bridge `disasm` request and
  `BridgeClient::disasm` use `limit` with zero or omission meaning unlimited.
- Move the test runner into the non-published `xtask` workspace package. Use
  `cargo xtask test` to share a temporary fixture across test suites; root Cargo
  commands still select `ghidra-cli` by default.
- Require `bridge_info.explicit_addresses: true` before program dispatch.
  Running bridges from older releases must be restarted; the CLI refuses the
  request without an address compatibility downgrade. Save and stop bridges
  with the old CLI before upgrading; see [upgrade steps](docs/runtime.md#upgrading).
- Group bridge controls under `bridge start|stop|restart|status|ping`. Replace
  `jobs [JOB_ID]` with `job list` or `job get JOB_ID`, and `cancel [JOB_ID]` with
  `job cancel [JOB_ID]`, which still defaults to the active job. The former
  top-level commands are removed.
- Move `query imports` and `query exports` to `program imports` and
  `program exports`, retaining their fields and shared query options.
- Move top-level `stats` to `program stats`, preserving statistics and query options.
- Move `patch bytes ADDRESS HEX` to `memory write ADDRESS HEX` and the bridge
  command `memory_write`. Byte validation, code-unit clearing, and automatic saving
  retain their existing behavior.
- Consolidate `summary` into `program info`, including query/output options, and
  `set-default` into `config set default_program|default_project VALUE`.

### Removed

- Replace the top-level `disasm-at` command (briefly renamed `disassemble-at`)
  with `define-code`. The `disasm_at` bridge command and `BridgeClient::disasm_at`
  are replaced by `define_code`; query flags and instruction-row output are no
  longer supported. The separate `clear --disassemble-at` option remains available.
- Remove `--target` from `function delete` and code definition; use a positional
  target with `function delete TARGET` or `define-code TARGET`.
- Remove `--filter`, `--sort`, `--offset`, `--limit`, and `--count` from
  `comment delete`. It still deletes EOL, PRE, POST, and PLATE comments at the
  supplied address and supports receipt field selection and output formatting.
- Remove obsolete Rust query APIs (`DataType`, `Query::new`, and the query builder
  methods) and client adapters for removed commands, including patching, diffing,
  legacy searches, inline scripts, graph export, and function tags.
- Remove the `program export` format aliases `cpp`, `bin`, and `ascii` from
  both the CLI and bridge. Use `c`, `binary`, and `asm`, respectively; format
  names remain case-insensitive and exported content is unchanged.
- Remove `xref list` and the `xrefs_list` bridge command without compatibility
  aliases. Use `xref to` and `xref from` for incoming and outgoing references.
- Remove `program export json`. Use `program info --json` and
  `function list --json --limit 0 --fields name,address,size` for JSON metadata
  and function lists; redirect stdout to save them to files.
- Remove `analyzer run`, the `analyze_run` bridge command, and
  `BridgeClient::analyze_run` without compatibility aliases. Use `analyze` or
  `BridgeClient::analyze` for full analysis with the current analyzer settings,
  including reanalysis. Existing `analyze` output and automatic saving are unchanged.
- Remove `--format ids` in favor of `--format minimal`, and remove
  `--format count`; `--count` retains its existing query semantics.
- Remove the unused `aliases` configuration field.
- Remove `--filter`, `--sort`, `--offset`, `--limit`, and `--count` from
  `function delete`. Target selection and receipt formatting are unchanged.
- Remove `--format tree` and `--format hex`. `program export hex` is unchanged.
- Remove `clear --to-data`. Plain `clear START:END` still clears without
  disassembly; `--disassemble-at ADDRESS` remains available.
- Remove the implicit raw-memory fallback from `find string`; it now searches
  only defined strings, case-insensitively. Use `find text` for encoded text in
  memory, or `find bytes` for hexadecimal byte patterns.
- Remove `query`; use `function list`, `string list`, `memory map`, and
  `program imports/exports`. Shared filtering and output options remain available.
- Remove `GHIDRA_DEFAULT_PROJECT` and `GHIDRA_DEFAULT_PROGRAM` target defaults
  and the batch-specific environment override handling. Select targets with CLI
  flags or config; omitted batch targets retain the batch project/current program.
- Remove the top-level `version` command; use `--version` or `-V`.
- Remove top-level `rename`/`mv` in favor of `symbol rename`, and remove
  `project create` and `init`. Import creates projects as needed; configuration
  works without initialization and can be updated with `config set`.
- Stop treating bare directories as project reservations. Project management
  recognizes `.gpr`/`.rep` artifacts and leaves bare directories intact.
- Remove the `patch`, `dump` (including top-level `export`), and `diff` namespaces,
  and the top-level `info` alias. Use `program export binary` for binary export
  and `program imports/exports` for symbol listings, or the corresponding list
  commands.
- Remove `memory search`, `find interesting`, `find crypto`, `find function`,
  `script java`, `script python`, and `graph export`.
- Remove `function x-refs`, `function decompile`, and `function tag`; use `xref`,
  `decompile`, and `tag`. Use `function list --filter` for function name searches.

## [0.5.0] - 2026-09-17

### Added

- `find instruction PATTERN` searches existing Ghidra instruction text with
  case-insensitive literal matching, optional `--case-sensitive`, and inclusive
  `--start`/`--end` bounds. It supports the usual query options and cancellation;
  it neither disassembles undefined bytes nor requires cross-references.
- `disasm TARGET --end END` lists existing instructions whose start addresses
  lie in the inclusive range. It rejects `--instructions` together with `--end`,
  reversed ranges, and bounds in different address spaces. Range queries honor
  `--limit` (including zero), filtering, sorting, offsets, and counts.
- Explicit `--format c` and `--format asm` render decompiled C and instruction
  text, including addresses, bytes, mnemonics, and operands for disassembly.
  Output defaults remain human-readable on TTY and compact JSON on non-TTY.
  Results containing rows without the required code fields, including after
  `--fields` projection, retain a single JSON document.
- `doctor --runtime` creates a disposable project, starts and pings the real
  Ghidra bridge, verifies clean shutdown, and removes the project. It reports
  Ghidra's settings/cache paths and retains the diagnostic project if shutdown
  fails. Without `--runtime`, JVM startup is explicitly reported as `not_checked`.

### Changed

- `program list` reports Ghidra's recorded analysis-completion flag instead of
  estimating it from the function count. Missing or unreadable flags are `null`.
  Import analysis, `analyze`, and `analyzer run` record successful completion;
  a cancelled first analysis does not create a completed flag.
- Function, symbol, type, string and comment lists push a single contains filter
  and safe offset/limit into Ghidra, including query/dump aliases, reducing JSON
  generation and transfer. Supported filter fields are `name` for functions,
  symbols, and types, `value` for strings, and `text` for comments. Sort, count,
  projection and other filters stay in Rust. Default limits, unlimited requests,
  page counts and batch output retain their semantics. Restart running bridges
  after upgrading; there is no old-bridge query fallback. Java/Rust Unicode
  lowercasing differences can still miss contains matches or shift page results;
  see [query execution](src/query/README.md#boundaries-and-validation).
- `batch` writes attempted results to stdout even on partial failure, preserving
  nonzero exit codes and stop policies. Stderr no longer carries `detail.results`.
- `find calls TARGET` searches the selected program for incoming call sites;
  `function calls TARGET` retains outgoing calls. Resolved thunks and import
  pointers are followed without treating ordinary data references as calls.
  Incoming rows include `caller`, `caller_address`, and `via` alongside the call
  site and callee; unresolved function-pointer calls are not inferred.
- `doctor` checks storage create/write/rename/delete operations and loopback TCP
  bind/connect, with resolved paths and configuration sources in its report.
- Bridge lifecycle operations use persistent OS-backed `.starting` locks. Save
  and stop every running bridge with the old CLI before upgrading: old and new lock
  protocols cannot coordinate. The new CLI also refuses to stop a legacy bridge
  that cannot confirm its final save through `shutdown_wait`.
  See [upgrade instructions](docs/runtime.md#upgrading).
  Recovery never deletes Ghidra project locks or force-terminates a discovery PID.
- Shutdown uses one total timeout across lock acquisition, connection, response,
  and process exit. Timeout errors retain exit code 75 and preserve discovery
  and the live process instead of force-terminating it. Status checks no longer
  remove discovery files; a live recorded PID prevents cleanup or replacement
  startup even when its port is unreachable. `.starting` files persist after
  lock release and must not be deleted.
- Rust library list APIs (`BridgeClient::list_functions`, `list_strings`,
  `symbol_list`, `type_list`, and `comment_list`) now require an `offset` argument.
  `OneShotImportOptions` gains `program` for the saved file name, and
  `BridgeClient::find_calls` now requests incoming calls; use `function_calls`
  for outgoing calls. Added `function_disasm` and `symbol_get_by_name` adapters,
  plus `find_string_with_limit`, `find_bytes_with_limit`, and
  `find_interesting_with_limit`; the existing search adapters remain available.
- Moved the RE agent skill from `docs/skills/SKILL.md` to
  [docs/skills/ghidra-cli/SKILL.md](docs/skills/ghidra-cli/SKILL.md), with
  task-specific references for exploration, refinement, low-level analysis,
  programs, scripting, and batch workflows.
- Credited hitori-chan's downstream work in `LICENSE` for the instruction search,
  bounded disassembly, and C/assembly output feature inspiration.

### Fixed

- Explicit-offset `type add-field --size` rejects sizes Ghidra cannot honor
  before changing the structure, matching append behavior.
- Symbol deletion rejects generated dynamic labels and the global namespace
  before mutation, checks each deletion result, and reports `deleted`, `failed`,
  and `not_attempted` targets on partial failure. Successful receipts include the
  deleted symbol snapshots. Save failures retain those details. Target-selection
  filters no longer erase deletion receipts in standalone or batch output.
- `find crypto` uses correct SHA-256 and MD5 round constants in both little- and
  big-endian word order. SHA-512 constants are no longer mislabeled as SHA-256.
- `graph callers` and `find calls` share call-site validation and thunk/pointer
  traversal. Argument references and non-call instructions are not callers.
- `diff functions --format` uses the shared output formats and flag precedence;
  unknown formats fail during argument parsing.
- `setup --version` resolves release numbers to official `Ghidra_VERSION_build`
  tags. `config set java_home PATH` now saves the configured JDK.
- `script run -` uses the JDK parser to require exactly one top-level public
  class, accepting modifiers and ignoring apparent declarations in comments,
  strings, and nested classes. Invalid syntax reports its line and column before
  execution; compilation and loading still use Ghidra's script bundle.
- `status` counts project files in subfolders consistently with `program list`.
- Function lookup errors recommend an executable help command instead of an
  invalid bare-word filter.
- Search and list output share one query limit plan. `find bytes`, raw-memory
  `find string`, and `find interesting` no longer truncate at 100/50 matches,
  so counts, filters, sorts and offsets can use the complete result set.
  Long searches check cancellation. Commands without bridge-side limits now
  honor `default_limit` with omitted query options or `--fields` alone, including
  in batches; explicit `--limit 0` remains unlimited.
- `function disasm` lists only the selected function's instructions, including
  disjoint body ranges and when selected by an interior address. It honors query
  limits, filtering, sorting, pagination, and counts without a hidden ten-instruction
  cap or spillover into neighboring functions. A distinct `function_disasm`
  bridge request prevents older bridges from silently returning a partial body.
- `disasm-at` and incomplete `clear --disasm-at` now fail with retained
  diagnostics, so `batch --on-error stop` stops before dependent edits. Successful
  clearing is still saved and reported as a partial change when redisassembly fails.
- `strings refs` applies counts, field selection, filters, sorting, and pagination
  to reference rows instead of its response envelope.
- Symbol lookup prefers exact names over bare hexadecimal addresses; rename/delete
  use name-only lookup so names such as `dead` remain editable. Explicit `0x`/`0X`
  addresses remain available to `symbol get`. Mutations use the distinct
  `symbol_get_by_name` bridge request so older bridges fail before editing.
- `program list` includes nested project folders and correctly identifies the
  current program among files sharing the same name.
- `project info` honors the global project and configured default when its name
  is omitted, and recognizes empty reservations created by `project create`.
- `--projects-dir` takes precedence over `GHIDRA_PROJECT_DIR` without changing
  environment variables or saved configuration, including per-line batch overrides.
- Script artifact examples use JSONL for minimum-row checks. Help documents
  `.jsonl`/`.ndjson` support and marks CSV row counting as WIP.
- Table, CSV, and TSV columns include keys from every output row, so fields
  present only in later rows are no longer silently dropped. Missing cells stay
  empty; existing column order and CSV/TSV escaping are preserved.
- CLI tests without Ghidra cover reservation deletion and preservation of project
  files when Ghidra is unavailable; real project deletion runs in Ghidra integration tests.
- Windows import tests normalize Ghidra's `/C:/...` executable paths before
  comparing them with native filesystem paths.
- Project deletion holds the CLI lifecycle lock through removal and acquires
  Ghidra's project lock, refusing deletion while an external Ghidra owner is active.
  Deleting `.gpr`/`.rep` artifacts now requires a working Ghidra/JDK installation;
  missing prerequisites preserve project files. Empty reservations can still be
  deleted without Ghidra, and unrelated files in the bare project directory remain.
- Stop, restart, and project deletion report final save failures and retain the
  JVM/program for recovery. Successful shutdown waits for accepted jobs and saving.
- Import rejects unsupported loader option names before loading or saving a
  program, reporting `import_status: not_started`. `--compiler-spec` now requires
  `--language`, and an explicit `--program` must be a single nonempty file name.
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
- Fallback fixed-width type aliases retain their widths across target ABIs. Type/field
  applicability, size, memory-range, and field-layout checks precede destructive
  edits. Struct, enum, and typedef creation report the actual registered name and
  path, including conflict suffixes. `type add-field --size` is honored when
  appending, or rejected before mutation if Ghidra cannot represent that size;
  existing field settings are preserved.
- Symbol edits revalidate selected IDs and metadata before changing any target;
  address selectors accept equivalent hex spellings while retaining address spaces.
- `patch bytes` validates that the complete range is mapped and initialized
  before clearing code. Patches spanning multiple memory blocks restore every
  affected block's write permission.
- `comment get` and `comment list` return comments at interior addresses of
  instructions and data, instead of requiring a code-unit start address.
- `find bytes` rejects empty or incomplete hexadecimal patterns. `find function`
  treats glob punctuation other than `*` literally. Raw-memory `find string`
  results retain the match in long printable runs and add a `truncated` flag
  indicating printable bytes outside the returned window.
- DOT graph output escapes identifiers and labels, preserving address-space
  separators instead of replacing them with underscores.
- Configured output format is honored after explicit flags. Default limits apply
  after client filtering, sorting, and offset, except for counts or explicit zero.
  Batch query lines inherit the batch selection despite environment defaults.
- Compatibility restart preserves the actual selected program file path and
  propagates stop failures instead of starting a replacement JVM.
- Configuration updates use locked atomic replacement and preserve config
  symlinks and unrelated settings, including concurrent updates on Windows.
  `init` preserves existing configuration; invalid output-format values and
  dangling config symlinks fail without replacing the previous file. Setup
  validates private staging before publication, reuses valid installations,
  refuses incomplete existing destinations, and saves absolute paths.
- Unavailable file logging no longer prevents commands from running. The CLI
  reports logging setup failures only when verbose diagnostics are requested
  without `--quiet`.
- Job cancellation is isolated, completed history retains metadata only, and
  shutdown remains responsive with a full queue. Pcode work uses the active
  cancellation monitor. Artifact hash failures return errors.
- CI unit coverage includes both library and binary targets. Ghidra integration
  and release test jobs initialize and verify the runtime with `doctor --runtime`
  before parallel JVM startup, and infrastructure coverage includes import/bootstrap recovery.
  Shutdown deadline tests no longer hang waiting for mock TCP servers.

### Removed

- Removed `diff programs`, `BridgeClient::diff_programs`, and the `diff_programs`
  bridge request. The command returned the current program's statistics without
  comparing the requested programs.
  `diff functions` remains available.
- Removed the unused `--detach` flags from import and analysis; commands wait
  for completion.
- Removed the bridge's `find_calls` request. Direct protocol clients must use
  `find_calls_to` for incoming calls or `function_calls` for outgoing calls.

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

[unreleased]: https://github.com/toratako/ghidra-cli/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/toratako/ghidra-cli/compare/v0.7.0-rc.1...v0.7.0
[0.7.0-rc.1]: https://github.com/toratako/ghidra-cli/compare/v0.6.1...v0.7.0-rc.1
[0.6.1]: https://github.com/toratako/ghidra-cli/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/toratako/ghidra-cli/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/toratako/ghidra-cli/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/toratako/ghidra-cli/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/toratako/ghidra-cli/compare/10019ba1f3b54c9edcca8ec644a30e16fb7b7c79...v0.3.0
[0.2.2]: https://github.com/toratako/ghidra-cli/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/toratako/ghidra-cli/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/toratako/ghidra-cli/releases/tag/v0.2.0
