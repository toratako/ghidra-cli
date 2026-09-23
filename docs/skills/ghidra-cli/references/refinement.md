# Refinement

Re-decompile after type, name, or signature edits to inspect the updated output.

## Function names, signatures, and variables

```bash
ghidra-cli function rename FUN_00401000 parse_header --project target
ghidra-cli function set-signature parse_header \
  --signature "int parse_header(char *buf, int len)" --project target
ghidra-cli function var list parse_header --filter 'kind=local' --project target
ghidra-cli function var get parse_header --var local_10 --project target
ghidra-cli function var set parse_header --var local_10 \
  --name header --type "Header *" --project target
ghidra-cli function set-return-type abort_path --type void --project target
ghidra-cli function get parse_header --with-signature --project target
ghidra-cli function set-noreturn abort_path --value true --project target
```

`function set-return-type` can save inferred parameter locations without fixing
their types.

`function get --with-signature` reads the Program prototype and ABI storage,
including hidden arguments and indirect returns; decompiler output can still
refine saved undefined parameter types. For thunks, the immediate target and final
signature owner can differ; signature edits affect the final owner. See
[thunk relationships](calls.md#thunk-relationships) to change the forwarding target.

Renaming an inferred local saves an undefined type so the decompiler continues
inferring it. Editing an inferred parameter can save the other inferred
parameters, including their types and storage.

```bash
ghidra-cli function var set parse_header --var value \
  --where 'kind=local AND first_use=0x00401234' --name length --project target
```

Automatic `this` parameters derive their type from the [class namespace](#symbols)
and calling convention. For ABI edits and saved stack layout, see
[calling convention and stack metadata](calls.md#calling-convention-and-stack-metadata).

For type definitions and data layouts, see [types](types.md#define-and-apply-types).
To check where a changed type or field is used, see [type usage searches](types.md#find-uses).

## Comments

`comment list` includes comments on external functions and unmapped addresses.

```bash
printf '%s' 'possible vtable load; verify callers' | \
  ghidra-cli comment set 0x401000 --stdin --project target
ghidra-cli comment set 0x401000 --file ./note.txt --project target

ghidra-cli bookmark set 0x401000 --text 'Check the jump table bounds' --category Review
ghidra-cli bookmark list --filter 'category=Review'
ghidra-cli bookmark delete 0x401000 --category Review
```

Bookmark identity is address, type, and category.

## Symbols

```bash
ghidra-cli symbol create-label 0x404000 packet_header --project target
ghidra-cli symbol rename packet_header message_header --project target
ghidra-cli namespace create app
ghidra-cli namespace create Widget --parent app --kind class
ghidra-cli symbol set-namespace dispatch --namespace app::Widget --address 0x401300
ghidra-cli symbol set-primary message_header --address 0x404000
```

Ambiguous symbol rename/delete requires `--address` or `--where`, or explicit
`--all` to affect every match. Rename/delete take exact names (even `0x...`);
`symbol get` accepts names or addresses.

Namespace paths start at global scope, such as `app::Widget`. Moving a function
into a class can change its native `this` parameter/type. Deleting a namespace
through `symbol delete` can also delete its children.

## References

```bash
ghidra-cli xref from 0x405020
ghidra-cli xref create 0x405020 0x401300 --operand 0 --type DATA
ghidra-cli xref create 0x401234 0x401300 --operand 0 --type COMPUTED_CALL
ghidra-cli xref delete 0x401234 0x401300 --operand 0
```

The zero-based `operand_index` and `source` from `xref from` identify an
existing reference. Editing an analysis-created reference requires
`--source ANALYSIS`.
`xref set-primary` chooses the representative destination for one operand,
including replacing an analysis-created primary. A reference can improve later
analysis, but does not establish that the decompiler recovered the indirect call.

## Named constants

```bash
ghidra-cli equate create READ_MODE 0x1
ghidra-cli equate attach READ_MODE --at 0x401234 --operand 1
ghidra-cli equate get READ_MODE
ghidra-cli equate detach READ_MODE --at 0x401234 --operand 1
```

`delete` removes the definition and all its uses. Decompiler-specific references
can have `operand_selectable: false`; an operand index cannot identify those uses safely.
`equate get` and `decompile` show named constants; `disassemble` keeps the
instruction's numeric operand representation.

## Function tags

```text
ghidra-cli function tag list
ghidra-cli function tag get <name>
ghidra-cli function tag create <name> --comment "…"
ghidra-cli function tag attach <tag>... --function <func>      # Attach existing tags
ghidra-cli function tag detach <tag>... --function <func>      # Detach tags (--all clears every tag)
ghidra-cli function tag rename <old> <new>
ghidra-cli function tag set-comment <name> --text "…"
ghidra-cli function tag delete <name>               # Delete tag, detaching from all functions
ghidra-cli function list --tag <name>      # Functions carrying a tag (repeatable = AND)
ghidra-cli function list --untagged
```

Tag names are case-sensitive; `--filter "tags ~ 'crypto'"` matches tag text.
`use_count` can include external functions; `function list --tag` lists
non-external functions.
