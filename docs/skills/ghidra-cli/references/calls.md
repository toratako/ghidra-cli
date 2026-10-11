# Calls and ABI

## Pointer and virtual-function tables

```bash
ghidra-cli memory read 0x405020 --size 64 --project target
ghidra-cli find address-tables --start 0x405000 --end 0x405fff --min-entries 3 --project target
ghidra-cli memory read-vtable 0x405020 --entries 8 --abi itanium --project target
ghidra-cli memory read-vtable 0x140005020 --entries 8 --abi msvc --project target
ghidra-cli memory read-vtable 0x405020 --entries 8 --abi itanium --encoding relative32 --project target
```

`memory read-vtable` starts at the address point (slot 0, where the object's vptr
points), which can differ from the table symbol. `relative32` reads LLVM's layout,
including its RTTI proxy. Slot count is supplied, not inferred; null and undefined
targets retain their slots. `complete` concerns slot bytes; `header.complete`
concerns ABI metadata.

`find address-tables` can find callback and dispatch tables. Bounds select starts,
so tables can extend past `--end`. Native boundary rules can split or miss tables;
scan completion is reported in `.meta`.

`find virtual-callers` searches calls through an absolute-pointer table.

```bash
ghidra-cli find virtual-callers Widget_draw --vtable 0x405020 --entries 8 --abi itanium --project target
ghidra-cli find virtual-callers Widget_draw --vtable 0x405020 --entries 8 --abi itanium --within dispatch --project target
```

In `evidence`, `table_value` traces the selected slot's address,
`table_type` associates a recovered table type, and `slot_offset` matches only an
offset. The latter two do not establish the runtime table. Branch merges and
trace failures appear in `.meta.scan.unresolved`. An incomplete scan or unreadable
table cannot rule out callers.

## Calling convention and stack metadata

```bash
ghidra-cli program list-calling-conventions --project target
ghidra-cli function set-calling-convention parse_header --convention __cdecl --project target
ghidra-cli function set-stack-purge parse_header --bytes 4 --project target
ghidra-cli function get parse_header --with-signature --with-frame --project target
```

`--with-frame` reads saved stack layout, including ABI-reserved space. Its size
is neither runtime stack usage nor stack purge; its owner identifies whose frame
is shown when inspecting a thunk.

## Explicit parameter and return locations

When a calling convention cannot express the observed ABI:

```bash
ghidra-cli function get decode --with-signature --project target
ghidra-cli program list-registers --filter 'name=EAX' --project target
ghidra-cli function set-storage decode --param-register input EAX --param-stack length 4 --project target
ghidra-cli function set-signature decode --signature 'long long decode(char *input, int length)' \
  --param-register input EAX --param-stack length 4 \
  --return-register-piece 0 EAX 4 --return-register-piece 4 EDX 4 --project target
```

`set-storage` uses saved parameter names and freezes the entire ABI, preserving
omitted locations and making automatic `this` explicit. `set-signature` with
storage options requires every parameter and non-void return location; without
them it uses convention-derived locations.

Piece offsets follow the value's memory byte order; the x86 little-endian example
places the return's low bytes in EAX and high bytes in EDX. Name a subregister to
select high register bytes; extended floats can use a wider piece such as
`--return-register-piece 0 ST0 10`.

Forced-indirect values require a full physical signature with pointer types and
hidden inputs spelled out. For thunks, edit the effective owner directly.

## Thunk relationships

```bash
ghidra-cli function set-thunk 0x401000 --target 0x402000 --project target
ghidra-cli function get 0x401000 --with-signature --project target
ghidra-cli function clear-thunk 0x401000 --project target
```

`set-thunk` changes the direct target, affecting thunks that forward through it,
without changing branch bytes. `clear-thunk` exposes the function's own saved
definition without copying the destination's signature.

## One call site's prototype

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

Saved overrides can outlive a patched call or body change. `get` reports their
applicability; `clear` addresses them by the original caller and address.
