# Scripting

```bash
ghidra-cli script list --project target
ghidra-cli script run ./scripts/Inspect.java --project target -- --arg value
ghidra-cli script run ./scripts/Inspect.java --expect-rows ./out.jsonl 10 --project target
ghidra-cli script run - --project target < ./scripts/Inspect.java
```

Script and expected artifact paths resolve from the CLI working directory.
`--expect` requires nonempty artifacts; `--allow-empty` permits empty files
without waiving `--expect-rows` minimums.

Stdin source must declare exactly one top-level public class extending
`GhidraScript`. Ghidra uses the file script's parent directory as its source bundle,
including supporting source files there.
