# Agent Instructions

This CLI primarily serves AI agents. Keep the README a short setup/usage entry
point; route detail through the [documentation map](docs/README.md).
`docs/skills` is currently a private Hina skill mirror, not the project-wide
source of truth. Keep implemented behavior separate from future plans.

- Never skip tests because Ghidra is missing: `require_ghidra!()` must fail when
  `ghidra doctor` fails. See [test commands and coverage](tests/README.md).
- Preserve output defaults: human-readable on TTY, `JsonCompact` on non-TTY;
  `--json` and `--pretty` explicitly select JSON. Agent focus does not change this.
- The persistent server is a Java bridge inside Ghidra, one per project; no Rust
  daemon. Launch uses `analyzeHeadless -preScript -noanalysis`.
- Register every new Java source in `src/ghidra/bridge/sources.rs`; startup and
  doctor must use the same complete bundle.
- Run program operations on the original GhidraScript thread. Handlers retain
  `ProgramSession`, never a cached Program or job monitor.
- Mutations use `ProgramSession.transaction()`: nested aborts can erase earlier
  successful requests. Failed nested handlers may retain partial changes.

See [CLI routing](src/app/README.md), [bridge lifecycle](src/ghidra/README.md),
[Java ownership/transactions](src/ghidra/scripts/ghidracli/README.md), and
[wire protocol](src/ipc/README.md) for scoped implementation constraints.
