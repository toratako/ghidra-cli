# Agent Instructions

This CLI primarily serves AI agents. The [skill](docs/skills/SKILL.md) is for AI
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
  `ProgramSession`, never a cached Program/monitor, and mutate through
  `session.transaction()`. End each request transaction and save before replying;
  never hide save failures. See [Java ownership and nested-transaction
  boundaries](src/ghidra/scripts/ghidracli/README.md).

See [CLI routing](src/app/README.md) and [wire protocol](src/ipc/README.md) for
dispatch/output constraints.

## Cross-platform paths

Path and lifecycle changes must follow the shared
[cross-platform helpers](src/ghidra/README.md#cross-platform-paths) and
[native-platform validation requirements](tests/README.md#cross-platform-changes).

## Owner Notes (Do NOT edit this section by $agent-instruction-prune)

- Do NOT prune @CHANGELOG.md
