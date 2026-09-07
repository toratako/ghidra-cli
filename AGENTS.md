# Agent Instructions

## Critical Rules

1. **NEVER SKIP TESTS!** If Ghidra is not installed, the tests MUST fail. `require_ghidra!()` panics when `ghidra doctor` fails.
2. **DEFAULT OUTPUT FORMAT** should be human and agent readable, NOT JSON. Use `--json` and `--pretty` for JSON output. Exception: when stdout is not a TTY (piped/scripted), the default auto-detects to `JsonCompact` for machine consumption — this is standard Unix pipe convention.

## Architecture

ghidra-cli uses a **direct bridge architecture**:
- CLI connects directly to a Java bridge running inside Ghidra's JVM via TCP
- The entry point is `GhidraCliBridge.java`, started via `analyzeHeadless -preScript -noanalysis`; implementation classes live in `src/ghidra/scripts/ghidracli/`
- Bridge binds `ServerSocket(0)` on localhost, writes port/PID files for discovery
- One bridge per project, identified by `~/.local/share/ghidra-cli/bridge-{md5}.port`
- Import/Analyze commands auto-start the bridge if not running
- No separate Rust daemon process — the Java bridge IS the persistent server
- `bridge/sources.rs` embeds the complete Java source bundle for both startup and doctor; register new Java files there
- Program operations run on the original GhidraScript thread. `ProgramSession` reads live script state; never cache a Program or job monitor in a handler
- Use `ProgramSession.transaction()` for handler mutations: aborting a nested Ghidra transaction can roll back earlier successful requests
