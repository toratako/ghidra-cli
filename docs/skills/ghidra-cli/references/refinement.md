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
ghidra-cli program list-calling-conventions --project target
ghidra-cli function set-calling-convention parse_header --convention __cdecl --project target
ghidra-cli function set-stack-purge parse_header --bytes 4 --project target
ghidra-cli function get parse_header --with-signature --with-frame --project target
ghidra-cli function set-noreturn abort_path --value true --project target
```

`function set-return-type` can save inferred parameter locations without fixing
their types.

`function get --with-signature` reads the Program prototype and ABI storage,
including hidden arguments and indirect returns; decompiler output can still
refine saved undefined parameter types. For thunks, the immediate target and final
signature owner can differ; signature edits affect the final owner.
`--with-frame` reads saved stack layout, including ABI-reserved space. Its size
is neither runtime stack usage nor stack purge; its owner identifies whose frame
is shown when inspecting a thunk.

Renaming an inferred local saves an undefined type so the decompiler continues
inferring it. Editing an inferred parameter can save the other inferred
parameters, including their types and storage; inspect
`function get --with-signature` afterward.

```bash
ghidra-cli function var set parse_header --var value \
  --where 'kind=local AND first_use=0x00401234' --name length --project target
```

Automatic `this` parameters derive their type from the [class namespace](#symbols)
and calling convention.

### Thunk relationships

```bash
ghidra-cli function set-thunk 0x401000 --target 0x402000 --project target
ghidra-cli function get 0x401000 --with-signature --project target
ghidra-cli function clear-thunk 0x401000 --project target
```

Set the relationship after identifying the forwarding destination. Editing a
thunk changes its direct target; other thunks that forward through it also resolve
through the new destination. This updates Ghidra's analysis model, not the branch
instruction. Clearing an incorrect relationship exposes the function's own saved
definition without copying the destination's signature. Inspect the returned
`after` signature before correcting its types or calling convention.

### One call site's prototype

```bash
ghidra-cli function call-signature get dispatch --at 0x401234 --project target
ghidra-cli function call-signature set dispatch --at 0x401234 \
  --signature 'int handler(Context *, int)' --convention __cdecl --project target
ghidra-cli decompile dispatch --project target
ghidra-cli function call-signature clear dispatch --at 0x401234 --project target
```

The target is the caller; the override applies only at `--at`, leaving the
callee's signature unchanged.
Omitting `--convention` uses the Program default rather than a callee or
decompiler guess.

Saved overrides can outlive a patched call or body change; inspect their
applicability with `get` and use `clear` with the original caller and address.

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
ghidra-cli xref create memory 0x405020 0x401300 --operand 0 --type DATA
ghidra-cli xref create memory 0x401234 0x401300 --operand 0 --type COMPUTED_CALL
ghidra-cli xref delete 0x401234 0x401300 --operand 0
```

Use the zero-based `operand_index` and `source` from `xref from` to select an
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
Inspect named constants with `equate get` and `decompile`; `disassemble` keeps
the instruction's numeric operand representation.

## Types

```bash
ghidra-cli type uses /Recovered/Header --kind signature --filter 'role=parameter'
ghidra-cli type uses /Recovered/Header --kind data
ghidra-cli type uses /Recovered/Header --kind variable --filter 'role=local'
ghidra-cli type field uses /Recovered/Header --field flags --function parse_packet
ghidra-cli type field uses /Recovered/Header --field flags --filter 'access=write'
```

Type uses follows typedefs, pointers and arrays. The default searches top-level
data and database signatures; `--kind variable` decompiles functions to find
parameters and locals, including inferred variables. Use a full type path to
distinguish same-named types.

Field uses distinguishes reads, writes and address-taking from the current
decompiler evidence. Passing a field's address to a call does not establish what
the callee does to it. `unknown` retains an identified field use whose access
cannot be classified. Check `meta.scan` before treating no matches as evidence:
failed decompilations and unresolved field identities make the search incomplete.
Even a completed scan depends on the current type recovery. Narrow expensive
semantic searches with `--function`; type edits can change their results.
Instruction locations follow High P-code provenance, so optimized expressions
can point to a consuming instruction. Inspect the function's disassembly when
the exact machine load or store matters.

```bash
ghidra-cli type get Header --project target
ghidra-cli type create struct Header --project target
ghidra-cli type field append Header --name magic --type uint --project target
ghidra-cli type field delete Header --field magic --project target
ghidra-cli type create enum Mode --member Unknown 0 --member Read 1 --member Write 2 --project target
ghidra-cli type enum member delete Mode --member Unknown --project target
ghidra-cli type create typedef HeaderAlias --type Header --project target
ghidra-cli type rename HeaderAlias PacketHeader --project target
ghidra-cli type delete PacketHeader --project target
ghidra-cli listing define-data 0x404000 --type Header --project target
ghidra-cli listing define-data 0x404000 --type Header --force --project target
ghidra-cli type import-c --category /Recovered \
  --code 'struct Vec3 { float x; float y; float z; }; typedef Vec3 *Vec3Ptr;' \
  --project target
```

`type import-c` parses C declarations without preprocessing or include-path
resolution. `--file` input is UTF-8 and resolves from the CLI working directory.

```bash
ghidra-cli type import-c --file recovered_types.h --category /Recovered
ghidra-cli type import-c --stdin --category /Recovered < recovered_types.h
```

`listing define-data --force` clears conflicting code or data units, including instructions,
before applying the type.

Type expressions accept `byte[16]`, `Hook *[8]`, and `byte[2][3]`;
sizes follow the program's data organization. Use paths such as
`/Recovered/Hook *[8]` to disambiguate categories.

Fallback aliases `uintN_t`/`uN` and `intN_t`/`sN` have fixed widths for N = 8, 16,
32, or 64 bits. Existing types with the requested name take precedence;
ordinary C spellings such as `unsigned int` use the target ABI.

`type rename` cannot rename primitive, array, or pointer types; use
`type create typedef` for an alias.

### Reusing archived types

```bash
ghidra-cli type archive list sdk.gdt --filter 'category^"/SDK"' --project target
ghidra-cli type import-gdt sdk.gdt --where 'path="/SDK/Header"' --project target
ghidra-cli listing define-data 0x404000 --type /SDK/Header --project target
ghidra-cli type export-gdt protocol.gdt --where 'category^"/Protocol"' --project target
```

Selection chooses root definitions; referenced types travel with them, including
dependencies outside the selected category. Use `--all` to select every root.
Import registers definitions in the Program; apply them where the binary supports
that interpretation. Archive listing needs a project bridge but no loaded Program.

Conflicting definitions or origins, and changes to ABI layout, reject the entire
import. Inspect the reported dependency path before changing the root selection;
an incompatible dependency can be shared by several roots. Use an archive built
for the target ABI when layout differs. An equivalent local definition can adopt
the archive's identity; `associated` reports that change. Export gives local
definitions new archive identities while preserving existing file-archive origins.
GDT cannot retain field-specific interpretation settings such as an endian override;
a settings conflict on export means those definitions need a representation the
archive can preserve before sharing them.

### Trying a separate type definition

```bash
ghidra-cli type category create /Draft
ghidra-cli type clone /Recovered/Header HeaderV2 --category /Draft
ghidra-cli type resize /Draft/HeaderV2 --size 64
ghidra-cli type move /Draft/HeaderV2 --category /Recovered
```

Clone separates only the top-level definition. Referenced types remain shared;
cloning `Node` to `NodeV2` leaves `next` pointing to `Node *`.

Resize adjusts the undefined tail of a non-packed structure. It cannot remove
defined fields, including explicit padding arrays. Size changes propagate to
containing types and applied data. Use an unapplied clone when experimenting
with a layout that cannot fit existing uses.

### Recovering unions

```bash
ghidra-cli type create union Payload
ghidra-cli type field append Payload --name integer --type uint32_t
ghidra-cli type field append Payload --name bytes --type 'byte[8]'
ghidra-cli type get Payload
ghidra-cli type field set Payload --ordinal 1 --type 'Header *' --name header
ghidra-cli type field set Payload --ordinal 1 --comment 'Used when tag == 2'
ghidra-cli type field delete Payload --ordinal 0
```

Unnamed union members require `--ordinal` from `type get`; deletion renumbers ordinals.

### Growing recovered structures

Inspect Ghidra's layout candidate for a variable before defining its type:

```bash
ghidra-cli function var infer-struct dispatch --var manager --with-accesses
```

The candidate comes from the selected function. Its size is not the object's
proven allocation size, and gaps are not recovered fields. Access records are
the LOAD/STORE evidence retained by Ghidra's helper, not an exhaustive access
search. If the variable is split into partial HighVariables, inspect
`pcode function dispatch --high` before choosing a different root.

```bash
ghidra-cli type field set Manager --offset 0x1c --name hook --type 'Hook *'
ghidra-cli type field set Manager --field hook --comment 'Called during shutdown'
ghidra-cli type field set Manager --field hook --comment ''
ghidra-cli type field clear Manager --offset 0x1c
```

Field offsets must be exact starts. In undefined space, `field set` requires `--type`.

Shrinking a field leaves undefined bytes. Growing consumes undefined space or
extends the structure, but cannot overwrite another defined field.
For types that need an explicit length, use `--type string --size 8` with
`field append` or `field set`.

`field clear` replaces the field with undefined bytes and preserves structure
size and later offsets, though component ordinals can change. `field delete`
removes ordinary fields' bytes and shifts later fields. Deleting a bitfield in
a non-packed structure leaves the byte layout unchanged.

Packed structures allow name/comment edits, but reject field type changes and
clearing defined fields. Bit-fields and zero-length fields cannot be edited with
offset commands.

In `type get`, an unnamed field has `name: null`; `display_name` gives its
generated name, which cannot be used with `--field`.

### Placing recovered bitfields

```bash
ghidra-cli type field create-bitfield Flags --offset 0 --storage-size 4 \
  --bit-offset 0 --bit-size 3 --type uint32_t --name mode
ghidra-cli type field set Flags --field mode --bit-size 4
ghidra-cli type field clear Flags --field mode
```

The placement range is read as a Program-endian integer; bit offset zero is its
least significant bit. Ghidra normalizes the result to the smallest byte range,
so the example's field starts at byte 0 on little-endian and byte 3 on big-endian.

Width edits stay within that current minimal range, even if creation specified
a larger storage size. Select bitfields by real name or a fresh ordinal because
several fields can share one byte. For ABI-driven packing, use a C declaration
with `import-c`.

## Function tags

```text
ghidra-cli tag list
ghidra-cli tag get <name>
ghidra-cli tag create <name> --comment "…"
ghidra-cli tag attach <tag>... --function <func>      # Attach existing tags
ghidra-cli tag detach <tag>... --function <func>      # Detach tags (--all clears every tag)
ghidra-cli tag rename <old> <new>
ghidra-cli tag set-comment <name> --text "…"
ghidra-cli tag delete <name>               # Delete tag, detaching from all functions
ghidra-cli function list --tag <name>      # Functions carrying a tag (repeatable = AND)
ghidra-cli function list --untagged
```

Tag names are case-sensitive; `--filter "tags ~ 'crypto'"` matches tag text.
`use_count` can include external functions; `function list --tag` lists
non-external functions.
