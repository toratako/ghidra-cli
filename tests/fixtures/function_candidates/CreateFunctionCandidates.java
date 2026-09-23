import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import java.math.BigInteger;

/** Explicit listing/reference facts, including plausible-looking false positives. */
public class CreateFunctionCandidates extends GhidraScript {
    private long nextCaller = 0x1800;

    private Address a(long offset) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }

    private void block(String name, long start, long size, boolean execute) throws Exception {
        currentProgram.getMemory().createInitializedBlock(name, a(start), size,
            (byte) 0xcc, monitor, false).setExecute(execute);
    }

    private void code(Address address, int... values) throws Exception {
        byte[] bytes = new byte[values.length];
        for (int i = 0; i < values.length; i++) bytes[i] = (byte) values[i];
        currentProgram.getMemory().setBytes(address, bytes);
        check(new DisassembleCommand(address, new AddressSet(address, address.add(bytes.length - 1)), false)
            .applyTo(currentProgram, monitor), "disassemble " + address);
        check(currentProgram.getListing().getInstructionAt(address) != null,
            "missing fixture instruction at " + address);
    }

    private void code(long address, int... values) throws Exception { code(a(address), values); }

    private void label(long address, String name) throws Exception {
        currentProgram.getSymbolTable().createLabel(a(address), name, SourceType.USER_DEFINED);
    }

    private void reference(Address from, Address to, RefType type, int operand) {
        currentProgram.getReferenceManager().addMemoryReference(from, to, type,
            SourceType.USER_DEFINED, operand);
    }

    private void reference(long from, long to, RefType type, int operand) {
        reference(a(from), a(to), type, operand);
    }

    private void call(long from, long to) throws Exception {
        long displacement = to - from - 5;
        code(from, 0xe8, (int) displacement, (int) (displacement >> 8),
            (int) (displacement >> 16), (int) (displacement >> 24));
        check(currentProgram.getListing().getInstructionAt(a(from)).getFlowType().isCall(),
            "fixture CALL at " + a(from));
    }

    private void call(long to) throws Exception {
        call(nextCaller, to);
        nextCaller += 0x10;
    }

    private void x86() throws Exception {
        block("callers", 0x1100, 0x1000, true);
        block("candidates", 0x3000, 0x400, true);
        block(".plt", 0x4000, 0x20, true);
        block("non_executable", 0x5000, 0x20, false);
        currentProgram.getMemory().createUninitializedBlock("uninitialized", a(0x6000), 0x20, false)
            .setExecute(true);
        block("pointer_data", 0x7000, 0x100, false);

        // A single call and a one-instruction return are enough; no prologue score.
        code(0x3000, 0xc3);
        label(0x3000, "single_candidate");
        call(0x1100, 0x3000);
        currentProgram.getFunctionManager().createFunction("single_caller", a(0x1100),
            new AddressSet(a(0x1100), a(0x1104)), SourceType.USER_DEFINED);

        code(0x3020, 0xc3);
        label(0x3020, "popular_candidate");
        for (int i = 0; i < 7; i++) call(0x1120 + 0x10 * i, 0x3020);
        // Same instruction, distinct operand: a reference count is not a call count.
        reference(0x1120, 0x3020, RefType.UNCONDITIONAL_CALL, 1);

        code(0x3040, 0xc3);
        label(0x3040, "computed_candidate");
        code(0x1200, 0xff, 0xd0);
        reference(0x1200, 0x3040, RefType.COMPUTED_CALL, 0);
        code(0x3048, 0xc3);
        label(0x3048, "second_computed_candidate");
        reference(0x1200, 0x3048, RefType.COMPUTED_CALL, 0);

        code(0x3060, 0xc3);
        label(0x3060, "conditional_candidate");
        int delta = 0x3060 - 0x1220 - 6;
        code(0x1220, 0x0f, 0x85, delta, delta >> 8, delta >> 16, delta >> 24);
        currentProgram.getListing().getInstructionAt(a(0x1220)).setFlowOverride(FlowOverride.CALL);
        check(currentProgram.getListing().getInstructionAt(a(0x1220)).getFlowType().isCall(),
            "conditional call override");

        // A tail jump and a terminating instruction need not have a RET/prologue.
        code(0x3080, 0xe9, 0x7b, 0xff, 0xff, 0xff);
        label(0x3080, "tail_candidate");
        call(0x3080);
        code(0x30a0, 0xf4);
        label(0x30a0, "noreturn_candidate");
        call(0x30a0);
        code(0x30c0, 0xc3);
        call(0x30c0);

        for (long target : new long[] {0x30e0, 0x3100, 0x3120, 0x3160, 0x31a0,
                0x3260, 0x3280, 0x32a0, 0x32c0, 0x32e0, 0x3300, 0x3320, 0x3340}) {
            code(target, 0xc3);
        }
        reference(0x7000, 0x30e0, RefType.DATA, 0);
        code(0x1240, 0x90);
        reference(0x1240, 0x3100, RefType.UNCONDITIONAL_CALL, 0);
        call(0x1260, 0x3120);
        currentProgram.getListing().getInstructionAt(a(0x1260)).setFlowOverride(FlowOverride.BRANCH);
        reference(0x1260, 0x3120, RefType.UNCONDITIONAL_CALL, 1);

        code(0x313f, 0x90, 0xc3);
        call(0x3140);
        code(0x1280, 0x90);
        currentProgram.getListing().getInstructionAt(a(0x1280)).setFallThrough(a(0x3160));
        call(0x3160);
        // Suppression is effective even when the preceding physical opcode is NOP.
        code(0x317f, 0x90, 0xc3);
        currentProgram.getListing().getInstructionAt(a(0x317f)).setFallThrough(null);
        label(0x3180, "suppressed_fallthrough_candidate");
        call(0x3180);

        code(0x3190, 0xc3);
        AddressSet body = new AddressSet(a(0x3190));
        body.add(a(0x31a0));
        currentProgram.getFunctionManager().createFunction("disjoint_owner", a(0x3190), body,
            SourceType.USER_DEFINED);
        call(0x31a0);
        code(0x31c0, 0xb8, 1, 0, 0, 0, 0xc3);
        call(0x31c1);
        call(0x31e0); // Initialized executable bytes, but no listing instruction.
        currentProgram.getListing().createData(a(0x3200), ByteDataType.dataType);
        call(0x3200);
        code(0x3220, 0x90, 0xc3);
        currentProgram.getFunctionManager().createFunction("existing_function", a(0x3220),
            new AddressSet(a(0x3220), a(0x3221)), SourceType.USER_DEFINED);
        call(0x3220);
        call(0x3221);
        // Function body can contain a separately isolated instruction without fallthrough.
        AddressSet isolatedBody = new AddressSet(a(0x3240));
        isolatedBody.add(a(0x3260));
        currentProgram.getFunctionManager().createFunction("second_disjoint_owner", a(0x3240),
            isolatedBody, SourceType.USER_DEFINED);
        call(0x3260);
        reference(0x7008, 0x3280, RefType.UNCONDITIONAL_JUMP, 0);
        code(0x12a0, 0xff, 0xd0);
        reference(0x12a0, 0x32a0, RefType.DATA, 0);
        reference(0x12c0, 0x32c0, RefType.UNCONDITIONAL_CALL, 0); // No instruction source.
        call(0x12e0, 0x3220);
        reference(0x12e1, 0x32e0, RefType.UNCONDITIONAL_CALL, 0); // Interior source.

        // An override on a NOP has no p-code CALL to override, even if primary.
        code(0x1300, 0x90);
        var inert = currentProgram.getReferenceManager().addMemoryReference(a(0x1300), a(0x3300),
            RefType.CALL_OVERRIDE_UNCONDITIONAL, SourceType.USER_DEFINED, 0);
        currentProgram.getReferenceManager().setPrimary(inert, true);
        code(0x1320, 0xff, 0xd0);
        var inactive = currentProgram.getReferenceManager().addMemoryReference(a(0x1320), a(0x3320),
            RefType.CALL_OVERRIDE_UNCONDITIONAL, SourceType.USER_DEFINED, 0);
        currentProgram.getReferenceManager().setPrimary(inactive, false);
        code(0x1340, 0xff, 0xd0);
        for (int operand = 0; operand < 2; operand++) {
            var duplicate = currentProgram.getReferenceManager().addMemoryReference(a(0x1340),
                a(0x3340), RefType.CALL_OVERRIDE_UNCONDITIONAL, SourceType.USER_DEFINED, operand);
            currentProgram.getReferenceManager().setPrimary(duplicate, true);
        }

        // Native x86 recognizes CALL-next as address acquisition rather than CALL flow.
        // A stale saved CALL reference must not override that interpretation.
        code(0x3350, 0xe8, 0, 0, 0, 0);
        reference(0x3350, 0x3355, RefType.UNCONDITIONAL_CALL, 0);
        code(0x3355, 0x58, 0xc3); // call next; pop is not a new function entry.
        code(0x3360, 0xc3);
        label(0x3360, "override_candidate");
        code(0x1360, 0xff, 0xd0);
        code(0x33a0, 0xc3);
        reference(0x1360, 0x33a0, RefType.COMPUTED_CALL, 0);
        var active = currentProgram.getReferenceManager().addMemoryReference(a(0x1360), a(0x3360),
            RefType.CALL_OVERRIDE_UNCONDITIONAL, SourceType.USER_DEFINED, 0);
        currentProgram.getReferenceManager().setPrimary(active, true);
        code(0x3380, 0xc3);
        var stale = currentProgram.getReferenceManager().addMemoryReference(a(0x1100), a(0x3380),
            RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 1);
        currentProgram.getReferenceManager().setPrimary(stale, false);

        // CALLOTHER has a distinct native override path even without raw CALL flow.
        code(0x33c0, 0xc3);
        label(0x33c0, "callother_candidate");
        code(0x13a0, 0x0f, 0x31); // RDTSC is a pure rdtsc CALLOTHER, unlike INT's CALLIND.
        check(!currentProgram.getListing().getInstructionAt(a(0x13a0)).getFlowType().isCall(),
            "CALLOTHER fixture has no raw CALL flow");
        var callother = currentProgram.getReferenceManager().addMemoryReference(a(0x13a0), a(0x33c0),
            RefType.CALLOTHER_OVERRIDE_CALL, SourceType.USER_DEFINED, 0);
        currentProgram.getReferenceManager().setPrimary(callother, true);
        code(0x33e0, 0xc3);
        code(0x13c0, 0x0f, 0x31);
        var wrongOverride = currentProgram.getReferenceManager().addMemoryReference(a(0x13c0), a(0x33e0),
            RefType.CALL_OVERRIDE_UNCONDITIONAL, SourceType.USER_DEFINED, 0);
        currentProgram.getReferenceManager().setPrimary(wrongOverride, true);

        code(0x4000, 0xc3);
        label(0x4000, "plt_candidate");
        call(0x4000);
        code(0x5000, 0xc3);
        call(0x5000);
        call(0x6000);
        call(0x8000); // Unmapped target.

        var overlay = currentProgram.getMemory().createInitializedBlock("candidate_overlay",
            a(0x3000), 0x20, (byte) 0xcc, monitor, true);
        overlay.setExecute(true);
        code(overlay.getStart(), 0xc3);
        currentProgram.getSymbolTable().createLabel(overlay.getStart(), "overlay_candidate", SourceType.USER_DEFINED);
        code(0x1380, 0xff, 0xd0);
        reference(a(0x1380), overlay.getStart(), RefType.COMPUTED_CALL, 0);
        // Native direct CALL p-code must retain the overlay destination's identity.
        code(overlay.getStart().add(0x10), 0xe8, 0xeb, 0xff, 0xff, 0xff);
    }

    private void thumb() throws Exception {
        block("callers", 0x1100, 0x100, true);
        block("thumb_code", 0x3000, 0x80, true);
        currentProgram.getProgramContext().setValue(currentProgram.getRegister("TMode"),
            a(0x1100), a(0x117f), BigInteger.ONE);
        currentProgram.getProgramContext().setValue(currentProgram.getRegister("TMode"),
            a(0x3000), a(0x307f), BigInteger.ONE);
        code(0x3000, 0x70, 0x47); // bx lr: two-byte Thumb instruction.
        label(0x3000, "thumb_candidate");
        code(0x1100, 0x80, 0x47); // blx r0
        reference(0x1100, 0x3000, RefType.COMPUTED_CALL, 0);
        code(0x3020, 0x70, 0x47);
        code(0x1120, 0x80, 0x47);
        reference(0x1120, 0x3021, RefType.COMPUTED_CALL, 0); // Do not normalize odd interior addresses.
        code(0x303e, 0x00, 0xbf, 0x70, 0x47); // nop; bx lr
        code(0x1140, 0x80, 0x47);
        reference(0x1140, 0x3040, RefType.COMPUTED_CALL, 0);
        check(currentProgram.getListing().getInstructionAt(a(0x1100)).getFlowType().isCall(), "Thumb BLX");
        check(currentProgram.getListing().getInstructionAt(a(0x3000)).getLength() == 2, "Thumb mode retained");
    }

    private void mips() throws Exception {
        block("callers", 0x1100, 0x100, true);
        block("mips_code", 0x3000, 0x100, true);
        code(0x3000, 3, 0xe0, 0, 8, 0, 0, 0, 0); // jr ra; nop
        label(0x3000, "mips_candidate");
        code(0x3020, 3, 0xe0, 0, 8, 0, 0, 0, 0);
        code(0x3040, 0x14, 0x85, 0, 0x0f, 0, 0, 0, 0, 3, 0xe0, 0, 8, 0, 0, 0, 0);
        check(currentProgram.getListing().getInstructionAt(a(0x3048)) != null,
            "post-delay fallthrough instruction is defined");
        // Native JAL destinations: ordinary entry, return delay slot, branch delay slot,
        // and post-delay fallthrough. Only the first is a candidate.
        for (int i = 0; i < 4; i++) {
            long target = new long[] {0x3000, 0x3024, 0x3044, 0x3048}[i];
            long word = 0x0c000000L | (target >> 2);
            code(0x1100 + i * 0x10, (int) (word >> 24), (int) (word >> 16),
                (int) (word >> 8), (int) word, 0, 0, 0, 0);
        }
        check(currentProgram.getListing().getInstructionAt(a(0x3024)).isInDelaySlot(), "return delay slot");
        check(currentProgram.getListing().getInstructionAt(a(0x3044)).isInDelaySlot(), "branch delay slot");
        check(currentProgram.getListing().getInstructionAt(a(0x1100)).getFlowType().isCall(), "MIPS JAL");
    }

    public void run() throws Exception {
        String language = currentProgram.getLanguageID().toString();
        if (language.startsWith("ARM")) thumb();
        else if (language.startsWith("MIPS")) mips();
        else x86();
    }
}
