# Batch

See [batch basics](../SKILL.md#batch) and
[save and failure behavior](../SKILL.md#results-edits-and-jobs).

## Syntax

```text
function set-signature main --signature "int main(int argc, char **argv)"
```

Backslashes escape the next character outside quotes; single quotes preserve
literal text. Inside double quotes, backslashes escape `"`, `\`, `$`, and backticks.
Variables, command substitutions, and wildcards are never expanded. Empty lines
and lines starting with `#` are ignored.

Selected lines and nested files are validated before any command runs;
Program-dependent checks, such as function/type existence, occur during execution.
Nested batches inherit `--on-error` unless overridden.

## Dependent edits

`edits.ghidra`:

```text
function rename 0x401000 parse_header
comment set 0x401000 --text "Parses the packet header"
```

```bash
ghidra-cli batch ./edits.ghidra --on-error stop --project target --program target.bin
```

## Resuming

A batch stopped after a rolled-back command can resume at that command's source line:

```bash
ghidra-cli batch ./edits.ghidra --from-line 45 --on-error stop --project target --program target.bin
```

`--from-line` counts source lines, including comments and blank lines. Earlier
lines are neither validated nor executed.

## Target selection and query controls

Per-line `--project`/`--program` override the batch targets. Program switches
persist for subsequent lines in that project. See [query controls](exploration.md#query-controls).

For import inputs and program export destinations, see
[artifact paths](programs.md#export).

## Result structure

In JSON output, `.data.results` contains attempted commands in execution order.
Each result's `line` is the one-based source line number. The report's
`commands_executed` includes failed attempts; counts cover the selected range.
Nested batch reports appear within the containing command's result or error detail.
