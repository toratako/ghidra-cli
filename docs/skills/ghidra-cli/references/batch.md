# Batch

See [batch basics](../SKILL.md#basic-batch) for a query example,
and [save and failure behavior](../SKILL.md#results-edits-and-jobs)
for persistence and retry decisions.

## Syntax

A batch file has one subcommand per line, without `ghidra-cli`. Quote multiword arguments, for example:

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

Use `--on-error stop` when later edits depend on earlier commands succeeding.
Example `edits.ghidra`, replacing the address with the target function's address:

```text
function rename 0x401000 parse_header
comment set 0x401000 "Parses the packet header"
```

```bash
ghidra-cli batch ./edits.ghidra --on-error stop --project target --program target.bin
```

## Resuming

After a stopped command has rolled back, fix its line in the original file and
resume from that line without replaying completed edits:

```bash
ghidra-cli batch ./edits.ghidra --from-line 45 --on-error stop --project target --program target.bin
```

`--from-line` counts source lines, including comments and blank lines. Earlier
lines are neither validated nor executed.

## Target selection and query controls

Per-line `--project`/`--program` override the batch project/current selection;
omitted targets inherit the batch project/current selection. Program switches
persist for subsequent lines in that project. Filters, fields, sorting, limits,
and counts apply within each result; see [query controls](exploration.md#query-controls).

For import inputs and program export destinations, see
[artifact paths](programs.md#export).

## Result structure

In JSON output, `.data.results` contains attempted commands in execution order.
Each result's `line` is the one-based source line number. The report's
`commands_executed` includes failed attempts; counts cover the selected range.
Nested batch reports appear within the containing command's result or error detail.
