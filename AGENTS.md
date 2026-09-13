# Agent Instructions

This CLI primarily serves AI agents. [The skill](docs/skills/SKILL.md) owns the
RE command reference and agent-facing operational guidance. Installation,
configuration, and environment recovery belong in ordinary docs; implementation
and test documentation stay with their modules. Maintain each for its audience,
not a shared size target. External docs may link to `SKILL.md` as an entry point,
but must not depend on its internal reference layout. Keep future plans separate
from implemented behavior. See the [documentation map](docs/README.md).

Write only what helps the reader choose or act. Keep useful examples and
non-obvious constraints; omit explanations apparent from the examples, generic
advice, and repeated navigation. Brevity is not a reason to remove domain knowledge
or recovery guidance.

- Never skip tests because Ghidra is missing: `require_ghidra!()` must fail when
  `ghidra-cli doctor` fails. See [test commands and coverage](tests/README.md).
- Preserve output defaults: human-readable on TTY, `JsonCompact` on non-TTY;
  `--json` and `--pretty` explicitly select JSON. Agent focus does not change this.
- The persistent server is a Java bridge inside Ghidra, one per project; no Rust
  daemon. Launch uses `analyzeHeadless -preScript -noanalysis`.
- Register every new Java source in `src/ghidra/bridge/sources.rs`; startup and
  doctor must use the same complete bundle.
- Run program operations on the original GhidraScript thread. Handlers retain
  `ProgramSession`, never a cached Program or job monitor.
- Mutations use `ProgramSession.transaction()`: nested aborts can erase other
  changes in the same request. Failed nested handlers may retain partial changes.
  End each request transaction and save before replying; never hide save failures.

See [CLI routing](src/app/README.md), [bridge lifecycle](src/ghidra/README.md),
[Java ownership/transactions](src/ghidra/scripts/ghidracli/README.md), and
[wire protocol](src/ipc/README.md) for scoped implementation constraints.
