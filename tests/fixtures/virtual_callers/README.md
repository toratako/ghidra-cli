# Virtual caller fixtures

`CreateVirtualCallersFixture.java` creates ordinary saved Ghidra programs for
x86-64 and AArch64 without a host compiler. Both contain real indirect-call
instructions, matching and unrelated vtables, and separately registered table
types. Tables stay writable so the decompiler cannot replace indirect calls
with constants from the saved image.

The x86 calls include memory-indirect and separate LOAD/CALL instructions;
AArch64 always separates LOAD and BLR. Exact instruction addresses distinguish
the actual call from the earlier slot load. Unknown vptrs, same-name types in
different categories, and mixed phi flows exercise the evidence boundary.
Repeated slots and an explicit thunk check target matching independently of
caller tracing. An unmapped function and a table at the end of mapped memory
exercise incomplete scans. Runtime slot indices and ordinary callback parameters
must remain unresolved; null pointers must not select the fixture function at
address zero. `CreateVirtualCallers32Fixture.java` supplies a smaller x86 fixture
to exercise four-byte pointer loads and slot strides.

`CheckVirtualCallersReadOnly.java` opens a separate read-only copy of the saved
database. Its test-owned proxy injects cancellation and native decompiler timeout
at the instruction callback, checks recovery and old-monitor isolation, and
verifies the database modification number and dirty state remain unchanged.

Run `cargo test --test virtual_callers_tests` with a working Ghidra/JDK setup.
