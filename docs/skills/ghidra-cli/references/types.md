# Types

## Find uses

```bash
ghidra-cli type uses /Recovered/Header --kind signature --filter 'role=parameter'
ghidra-cli type uses /Recovered/Header --kind data
ghidra-cli type uses /Recovered/Header --kind variable --filter 'role=local'
ghidra-cli type field uses /Recovered/Header --field flags --function parse_packet
ghidra-cli type field uses /Recovered/Header --field flags --filter 'access=write'
```

`type uses` follows typedefs, pointers and arrays. It searches top-level data and
saved signatures by default; `--kind variable` includes inferred decompiler
parameters and locals.

Field uses depend on current decompiler types. Passing a field's address to a call
does not establish the callee's access; `unknown` means an identified use could
not be classified. `meta.scan` reports failed decompilations and unresolved field
identities. High P-code locations can identify a consuming instruction rather
than the machine load or store.

## Define and apply types

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
sizes follow the program's data organization. Paths such as
`/Recovered/Hook *[8]` disambiguate categories.

Fallback aliases `uintN_t`/`uN` and `intN_t`/`sN` have fixed widths for N = 8, 16,
32, or 64 bits. Existing types with the requested name take precedence;
ordinary C spellings such as `unsigned int` use the target ABI.

`type rename` cannot rename primitive, array, or pointer types; use
`type create typedef` for an alias.

To share definitions across programs, see [GDT archives](programs.md#reusing-archived-types).

## Trying a separate type definition

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
containing types and applied data. An unapplied clone allows layout experiments
that cannot fit existing uses.

## Recovering unions

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

## Growing recovered structures

```bash
ghidra-cli function var infer-struct dispatch --var manager --with-accesses
```

The candidate uses only the selected function; its size does not prove allocation
size, and gaps are not recovered fields. Access records contain Ghidra's retained
LOAD/STORE evidence, not all accesses. Split HighVariable roots can be investigated
with `pcode function dispatch --high`.

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

## Placing recovered bitfields

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
a larger storage size. Several bitfields can share one byte; real names or current
ordinals distinguish them. C declarations via `import-c` provide ABI-driven packing.
