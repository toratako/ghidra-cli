# Agent Instructions

This CLI primarily serves AI agents. The [skill](docs/skills/ghidra-cli/SKILL.md) is for AI
agents doing reverse engineering (RE) with this CLI. Keep the skill and its
references self-contained: agents must not need other project docs to do RE work.
Include only information those agents need for that work.

Keep installation, configuration, and environment recovery docs outside the skill.
Keep implementation and test docs with their modules. Separate future plans from
implemented behavior. Other docs may link to `SKILL.md` as the entry point, but
must not depend on how the skill's references are organized.
See the [documentation map](docs/README.md).

Write for each document's audience. Keep useful examples, domain knowledge,
non-obvious constraints, and recovery steps. Do not remove these just to shorten
a document or meet a shared length target. Omit generic advice and repetition.

- Never skip tests because Ghidra is missing: `require_ghidra!()` must fail when
  `ghidra-cli doctor` fails. See [test commands and coverage](tests/README.md).
- Preserve output defaults: human-readable on TTY, `JsonCompact` on non-TTY;
  `--json` and `--pretty` explicitly select JSON.
- The persistent server is a Java bridge inside Ghidra, one per project; no Rust
  daemon. Launch uses `analyzeHeadless -preScript -noanalysis`.
- Register new Java sources in `src/ghidra/bridge/sources.rs` for both startup and
  doctor. See [bridge lifecycle and paths](src/ghidra/README.md).
- Program operations run on the original GhidraScript thread. Handlers retain
  `ProgramSession`, never a cached Program/monitor. `ProgramSession` owns request
  transactions and saving; ordinary handlers never start/end transactions or save.
  Roll back failed/cancelled ordinary requests and never hide save failures.
  See [Java ownership and transaction
  boundaries](src/ghidra/scripts/ghidracli/README.md).

See [CLI routing](src/app/README.md) and [wire protocol](src/ipc/README.md) for
dispatch/output constraints.

## Cross-platform paths

Path and lifecycle changes must follow the shared
[cross-platform helpers](src/ghidra/README.md#cross-platform-paths) and
[native-platform validation requirements](tests/README.md#cross-platform-changes).

## Owner Notes (Do NOT edit this section by $agent-instruction-prune)

- Do NOT prune @CHANGELOG.md
- Do not consider backward compatibility; instead, we are prioritizing aesthetic excellence in the CLI's design.
- When replacing a contract, remove obsolete paths and their tests together.
  Do not add legacy aliases, fallbacks, migration-only diagnostics, or tests
  enumerating rejected spellings of removed commands, options, or fields.
- Defensive code and tests must protect against a concrete failure under the
  current contract, such as wrong-target edits, data loss, or invalid input reaching
  a mutation. Test shared validation boundaries with representative inputs instead
  of duplicating parser behavior. Supported platforms and Ghidra versions are part
  of the current contract.

### Skill documentation

Add to `docs/skills` only when the text helps an RE agent choose an operation,
interpret results, or recover from failure. Technical correctness, a recent
feature change, or a regression test is not sufficient reason to add it.

Assume a capable agent. Omit what examples, general knowledge, `--help`, or
ordinary output already convey. Avoid inventories of unsupported options or
return fields, assurances of expected behavior, obscure validation bounds, and
comparisons with removed behavior. Explain fields and constraints when their
meaning affects an RE decision.

Keep useful command examples, non-obvious pitfalls, and concrete recovery steps.
Keep shared explanations in one place. Apply owner deletions to similar cases;
do not restore the same boilerplate under another command. Select for usefulness
rather than a line-count target.
