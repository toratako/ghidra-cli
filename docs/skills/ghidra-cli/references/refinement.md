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

`function rename` uses `--address` to disambiguate duplicate names.

`function edit-var` selects a local variable or parameter by exact name;
ambiguous names return candidates. `before` describes the decompiler's variable,
while `after` describes the updated database definition. A rename can leave the
database type undefined so the decompiler continues inferring it.

## Comments

`comment list` includes comments on external functions and unmapped addresses.
`comment delete ADDRESS` removes EOL, PRE, POST, and PLATE comments together.

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

`type import-c` parses C declarations without preprocessing or include-path
resolution. `--file` input is UTF-8 and resolves from the CLI working directory.

```bash
ghidra-cli type import-c --file recovered_types.h --category /Recovered
ghidra-cli type import-c --stdin --category /Recovered < recovered_types.h
```

`type create struct` accepts a bare name and creates an empty struct; use
`set-field`, `add-field`, or `import-c` for its definition.

`type apply --force` clears conflicting code or data units, including instructions,
before applying the type.

Type expressions accept pointers and fixed-length arrays, such as `byte[16]`,
`Hook *[8]`, and `byte[2][3]`. Sizes use the selected program's data organization.
Ambiguous short names fail with full paths in `detail.candidates`. Use `/Recovered/Hook` or
`/Recovered/Hook *[8]` to select a category explicitly.

Fallback aliases `uintN_t`/`uN` and `intN_t`/`sN` have fixed widths for N = 8, 16,
32, or 64 bits. Existing types with the requested name take precedence;
ordinary C spellings such as `unsigned int` use the target ABI.

`type delete` selects a registered program type by name or full path.
`type rename` cannot rename primitive, array, or pointer types; use
`type create typedef` for an alias.

### Growing recovered structures

```bash
ghidra-cli type set-field Manager --offset 0x1c --name hook --type 'Hook *'
ghidra-cli type set-field Manager --offset 0x1c --comment 'Called during shutdown'
ghidra-cli type set-field Manager --offset 0x1c --comment ''
ghidra-cli type clear-field Manager --offset 0x1c
```

`set-field` selects a field by its exact starting byte offset; omitted attributes
keep their current values. In undefined space, `--type` is required and `--name`
is optional. An empty comment clears it.

Shrinking a field leaves undefined bytes. Growing consumes undefined space or
extends the structure, but cannot overwrite another defined field.
`add-field` appends unless `--offset` is given. For fixed byte spans, use an
array type such as `byte[8]`; `--size` must match the size of the chosen type.

`clear-field` replaces the field with undefined bytes and preserves structure
size and later offsets. `del-field --name NAME` removes bytes and shifts later
fields.

Layout changes require packing to be disabled. Packed structures allow
name/comment edits, but reject type changes and clearing defined fields.
Bit-fields and zero-length fields cannot be edited with these offset commands.

In `type get`, an unnamed field has `name: null`; `display_name` gives its
generated name.

## Function tags

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

Tag names are case-sensitive; `--filter "tags ~ 'crypto'"` matches tag text.
