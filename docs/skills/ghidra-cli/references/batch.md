# Batch

See [batch basics](../SKILL.md#basic-batch) for a query example,
and [save and failure behavior](../SKILL.md#results-edits-and-jobs)
for persistence and retry decisions.

## Syntax

A batch file has one subcommand per line, without `ghidra-cli`. Quote multiword
arguments, for example:

```text
function set-signature main --signature "int main(int argc, char **argv)"
```

Backslashes escape the next character outside quotes; single quotes preserve
literal text. Inside double quotes, backslashes escape `"`, `\`, `$`, and backticks.
Variables, command substitutions, and wildcards are never expanded. Empty lines
and lines starting with `#` are ignored; malformed quoting fails that line and
follows the selected `--on-error` policy. Nested batches inherit the policy
unless overridden.

## Dependent edits

Use `--on-error stop` when later edits depend on earlier commands succeeding.
Commands execute sequentially, each with its own request boundary; the batch is
not atomic. A failed ordinary edit rolls back only that request, so completed
commands remain saved even when the batch stops.
Example `edits.ghidra`, replacing the address with the target function's address:

```text
function rename 0x401000 parse_header
comment set 0x401000 "Parses the packet header"
```

```bash
ghidra-cli batch ./edits.ghidra --on-error stop --project target --program target.bin
```

## Target selection and query controls

Per-line `--project`/`--program` override the batch project/current selection;
omitted targets inherit the batch project/current selection. Program switches
persist for subsequent lines in that project. Filters, fields, sorting, limits,
and counts apply within each result; see [query controls](exploration.md#query-controls).

For import inputs and program export destinations, see
[artifact paths](programs.md#export).

## Result structure

In JSON output, `.[0]` is the batch report:

| Field | Meaning |
|---|---|
| `commands_parsed` | Number of command lines, excluding blank lines and comments |
| `commands_executed` | Number of attempted commands, including failures |
| `failed` | Number of failed commands |
| `not_executed` | Commands left after execution stopped |
| `results` | Attempted commands in execution order |

Each result has `line` (the one-based source line number) and `command`. Successful
commands have `result`; failures have `error`, `exit_code`, and, when supplied by
the command, `detail`. Save and transaction-boundary failures also set
`save_failed: true` or `transaction_failed: true` on the report, respectively.
`detail.rolled_back: true` confirms rollback of the failed request;
`detail.save_failed: true` instead requires saving the retained edits without
replaying the command. Transaction-boundary failures, save failures, and timeouts
stop the batch regardless of `--on-error`. A completed rollback is an ordinary
command error and follows the selected policy.
Nested batch reports appear within the containing command's result or error
detail. A nonzero exit still leaves the report on stdout; stderr contains only
the batch diagnostic and summary.
