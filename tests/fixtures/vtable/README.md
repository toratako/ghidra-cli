# VTable fixtures

`CreateVtableFixture.java` fills a portable raw import using Ghidra's native
endianness. It declares the targets explicitly so tests distinguish mapped bytes,
function entries, null pointers, unmapped targets and thunks without analysis.
The MSVC 64-bit COL fields use the imported Program's image base.

`layout.elf.hex` and `relative.elf.hex` are complete ELF x86-64 relocatable objects
compiled from `layout.cpp` by Clang 22.1.8. Tests decode the hexadecimal text and
import it with Ghidra's ELF loader; CI needs no C++ compiler. Their virtual methods,
primary and secondary address points, RTTI and adjustment thunk are compiler
output, including relocations. The preparation script only creates labels and
Function records, never rewrites table bytes.

`msvc.coff.hex` is the same source compiled for MSVC x64. Ghidra's COFF loader
applies `IMAGE_REL_AMD64_ADDR64` to the slots and Complete Object Locator pointers,
and `IMAGE_REL_AMD64_ADDR32NB` to the COL's type/class/self RVAs. Both `Derived`
vftables are retained: their locator offsets are zero and eight, respectively.
Unlike Itanium's `_ZTV` symbol, each MSVC vftable symbol already names slot zero.

Regenerate from the repository root:

```sh
clang++ --target=x86_64-unknown-linux-gnu -std=c++17 -O1 -fno-exceptions \
  -fno-asynchronous-unwind-tables -fno-addrsig \
  -c tests/fixtures/vtable/layout.cpp -o /tmp/ghidra-vtable-layout.o
clang++ --target=x86_64-unknown-linux-gnu -std=c++17 -O1 -fno-exceptions \
  -fno-asynchronous-unwind-tables -fno-addrsig \
  -fexperimental-relative-c++-abi-vtables \
  -c tests/fixtures/vtable/layout.cpp -o /tmp/ghidra-vtable-relative.o
clang++ --target=x86_64-pc-windows-msvc -std=c++17 -O1 -fno-exceptions \
  -fno-asynchronous-unwind-tables -fno-addrsig \
  -c tests/fixtures/vtable/layout.cpp -o /tmp/ghidra-vtable-msvc.obj
python3 - <<'PY'
from pathlib import Path
for kind in ['layout', 'relative']:
    data = Path('/tmp/ghidra-vtable-' + kind + '.o').read_bytes()
    Path('tests/fixtures/vtable/' + kind + '.elf.hex').write_text(
        '\n'.join(data[i:i+32].hex() for i in range(0, len(data), 32)) + '\n')
data = Path('/tmp/ghidra-vtable-msvc.obj').read_bytes()
Path('tests/fixtures/vtable/msvc.coff.hex').write_text(
    '\n'.join(data[i:i+32].hex() for i in range(0, len(data), 32)) + '\n')
PY
```

The `Derived` table has seven components: offset-to-top, RTTI reference, two
primary slots, secondary offset-to-top (`-8`), the same RTTI reference, and a
secondary slot. Component widths are eight bytes normally and four with the
relative ABI. In the relative object, the second primary slot's `R_X86_64_PLT32`
relocation has addend `4`: both entries use the primary address point as their
base, not each slot's address. RTTI uses `R_X86_64_GOTPCREL` to reference the
absolute RTTI pointer in a proxy.

`CheckVtableReadOnly.java` invokes the same production handler against a separate
read-only Program, checking the modification number across successful, partial,
invalid and cancelled requests and recovery after cancellation.
