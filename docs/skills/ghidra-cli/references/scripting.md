# Scripting

```bash
ghidra-cli script list --project target
ghidra-cli script run ./scripts/Inspect.java --project target -- --arg value
ghidra-cli script run ./scripts/Inspect.java --expect-rows ./out.jsonl 10 --project target
ghidra-cli script run - --project target < ./scripts/Inspect.java
```

Script and expected artifact paths resolve from the CLI working directory.
Use `--expect PATH` for required nonempty artifacts or `--expect-rows PATH MIN_ROWS`
for a minimum row count; both can be repeated. `--allow-empty` permits expected
empty files but does not waive a minimum row count.

Stdin source must declare exactly one top-level public class extending
`GhidraScript`. Keep supporting source files in the file script's parent
directory, which Ghidra uses as its source bundle.
