# Refinement

Re-decompile after type, name, or signature edits to inspect the updated output.

## Function names, signatures, and variables

```bash
ghidra-cli function rename FUN_00401000 parse_header --project target
ghidra-cli function set-signature parse_header \
  --signature "int parse_header(char *buf, int len)" --project target
ghidra-cli function edit-var parse_header --var local_10 \
  --name header --type "Header *" --project target
ghidra-cli function set-return-type abort_path --type void --project target
ghidra-cli function set-calling-convention parse_header --convention __cdecl --project target
ghidra-cli function set-noreturn abort_path --project target
```

`function rename` uses `--address` to disambiguate the old name;
it does not accept `--filter` or `--all`.

`function delete TARGET` deletes one function by exact name or explicit address.
TARGET is a required positional argument; there is no `--target` option.
Use `--fields` and `--format` to format its deletion receipt. It does not accept
`--filter`, `--sort`, `--offset`, `--limit`, or `--count`.

`function edit-var FUNCTION --var CURRENT_NAME` edits a local variable or parameter
by exact name; ambiguous names fail with candidates. Supply `--name`, `--type`,
or both. Omitted attributes are not explicitly reassigned. `before` reports the
decompiler's variable and `after` the updated database definition, including name,
type/path, and storage. A rename can leave the database type undefined so the
decompiler continues inferring it. Known name conflicts and invalid types fail
before editing; other failures can retain partial changes.

## Comments

`comment get ADDRESS` and `comment list` read comments. `comment set` accepts
`--comment-type EOL` (default), `PRE`, `POST`, or `PLATE`.

`comment delete ADDRESS` deletes all four comment types at that address.
Like `function delete`, it accepts `--fields` and `--format` for the deletion
receipt, and rejects `--filter`, `--sort`, `--offset`, `--limit`, and `--count`.

Use stdin or a file to preserve comment text containing shell metacharacters:

```bash
printf '%s' 'possible vtable load; verify callers' | \
  ghidra-cli comment set 0x401000 --stdin --project target
ghidra-cli comment set 0x401000 --text-file ./note.txt --project target
```

## Symbols

```bash
ghidra-cli symbol create 0x404000 packet_header --project target
ghidra-cli symbol rename packet_header message_header --project target
```

Ambiguous symbol rename/delete requires `--address` or `--filter`, or explicit
`--all` to affect every match. Rename/delete take exact names (even `0x...`);
`symbol get` accepts names or addresses.

## Types

```bash
ghidra-cli type get Header --project target
ghidra-cli type create struct Header --project target
ghidra-cli type add-field Header --name magic --type uint --offset 0 --project target
ghidra-cli type del-field Header --name magic --project target
ghidra-cli type create enum Mode --values "Unknown=0,Read=1,Write=2" --project target
ghidra-cli type create typedef HeaderAlias Header --project target
ghidra-cli type rename HeaderAlias PacketHeader --project target
ghidra-cli type delete PacketHeader --project target
ghidra-cli type apply 0x404000 Header --project target
ghidra-cli type apply 0x404000 Header --force --project target
ghidra-cli type import-c --category /Recovered \
  'struct Vec3 { float x; float y; float z; }; typedef Vec3 *Vec3Ptr;' \
  --project target
```

`type import-c` accepts exactly one input: inline C code, `--file PATH`, or
`--stdin`. Files are UTF-8 and resolve from the CLI working directory. These
inputs use the same C declaration parser; file input does not add preprocessing
or include-path support.

```bash
ghidra-cli type import-c --file recovered_types.h --category /Recovered
ghidra-cli type import-c --stdin --category /Recovered < recovered_types.h
```

`type create struct` accepts a bare name and creates an empty struct; use
`set-field`, `add-field`, or `import-c` for its definition.

`type apply --force` clears a conflicting data unit before applying the type.
Type applicability, size, memory range, and field-layout checks precede
destructive edits. Later execution failures can still retain partial changes.

Type expressions accept pointers and fixed-length arrays, such as `byte[16]`,
`Hook *[8]`, and `byte[2][3]`. Array counts are positive decimal integers; sizes
use the selected program's data organization. Ambiguous short names fail with
full paths in `detail.candidates`. Use `/Recovered/Hook` or
`/Recovered/Hook *[8]` to select a category explicitly; an incorrect full path
does not fall back to another category.

Fallback aliases `uint8_t`/`u8`, `uint16_t`/`u16`, `uint32_t`/`u32`, and
`uint64_t`/`u64` have fixed widths of 1, 2, 4, and 8 bytes. Signed equivalents
use `intN_t`/`sN`. Existing types with the requested name take precedence;
ordinary C spellings such as `unsigned int` use the target ABI.

### Growing recovered structures

```bash
ghidra-cli type set-field Manager --offset 0x1c --name hook --type 'Hook *'
ghidra-cli type set-field Manager --offset 0x1c --comment 'Called during shutdown'
ghidra-cli type set-field Manager --offset 0x1c --comment ''
ghidra-cli type clear-field Manager --offset 0x1c
```

`set-field` selects a field by its exact starting byte offset. Supply one or more
of `--name`, `--type`, and `--comment`; omitted attributes keep their current
values. In undefined space, `--type` is required and `--name` is optional.
An empty comment clears it; an empty name is rejected. Offsets accept decimal
and `0x` hexadecimal, including on `add-field`.

Shrinking a field leaves undefined bytes. Growing consumes undefined space or
extends the structure, but cannot overwrite another defined field. Interior
offsets and name collisions fail with the existing field in `detail.field`;
overlaps list `detail.conflicts`. `add-field --offset` uses the same placement
checks; omitting its offset appends as before. With either form, `--size` must
match the length Ghidra assigns to the field; an unsupported size fails before
the structure changes. Use an array type such as `byte[8]` for fixed byte spans.

`clear-field` replaces the field with undefined bytes and preserves structure
size and later offsets. Clearing existing padding succeeds with `changed: false`;
an offset outside the structure fails. `del-field --name NAME` still removes
bytes and shifts later fields.

Layout changes require packing to be disabled. Packed structures allow
name/comment edits, but reject type changes and clearing defined fields.
Bit-fields and zero-length fields cannot be edited with these offset commands.

`set-field` and `clear-field` report `changed`, the structure's full `path`,
`offset`, `size_before`, `size_after`, and `before`/`after` field definitions.
`type get` includes `packing_enabled` and each field's `type_path` and `comment`.
An unnamed field has `name: null`; `display_name` gives its generated name.

## Function tags

Command forms (`<...>` denotes an argument to replace):

```text
ghidra-cli tag list                        # All tags (name, comment, use count)
ghidra-cli tag get <name>                  # Functions carrying a tag
ghidra-cli tag create <name> --comment "…" # Create a tag (comment optional)
ghidra-cli tag add <func> <tag>...         # Attach tags (auto-creates missing ones)
ghidra-cli tag remove <func> <tag>...      # Detach tags (--all clears every tag)
ghidra-cli tag rename <old> <new>          # Rename everywhere it is used
ghidra-cli tag set-comment <name> "…"      # Set/clear a tag's comment
ghidra-cli tag delete <name>               # Delete tag, detaching from all functions
ghidra-cli function list --tag <name>      # Filter by tag (repeatable = AND)
ghidra-cli function list --untagged        # Functions with no tags
```

Tag names are case-sensitive; `add`/`remove` report already-present/absent tags
without error. Function rows have a sorted `tags` array, supporting
`--fields name,address,tags` and `--filter "tags ~ 'crypto'"`.
