# Function candidate fixtures

`CreateFunctionCandidates.java` installs explicit instructions, references, and
function bodies in an unanalysed raw import. The fixture checks instruction kinds
and delay-slot/context assumptions against native Ghidra before the search runs.

The x86-32 and x86-64 cases pair valid direct, computed, conditional, and native
override calls with misleading references and instruction boundaries. They cover
single-instruction and nonreturning targets, duplicate call-site evidence, sample
truncation, existing disjoint bodies, nonlocal fallthrough overrides, PLT blocks,
and equal offsets in default/overlay spaces. A direct call inside the overlay
checks native p-code target identity. Thumb and big-endian MIPS cases exercise
instruction alignment/context and both branch/return delay slots.

`CheckFunctionCandidatesReadOnly.java` invokes the production handler against a
separately opened saved read-only program. It checks database modification state,
deterministic cancellation at several scan depths, recovery with fresh request
monitors, and limited-scan metadata. Rust assertions also reopen the fixture and
verify that creating one candidate removes exactly that result durably.
