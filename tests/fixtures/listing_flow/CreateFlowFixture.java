import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;

public class CreateFlowFixture extends GhidraScript {
    private Address a(long offset) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }

    private void code(long start, long end) throws Exception {
        check(new DisassembleCommand(a(start), new AddressSet(a(start), a(end)), false)
            .applyTo(currentProgram, monitor), "disassemble fixture at " + a(start));
    }

    private void function(String name, long start, long end) throws Exception {
        var function = currentProgram.getFunctionManager().createFunction(name, a(start),
            new AddressSet(a(start), a(end)), SourceType.USER_DEFINED);
        function.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED);
    }

    public void run() throws Exception {
        if (currentProgram.getLanguageID().toString().startsWith("MIPS")) {
            code(0x1000, 0x1007);
            code(0x1008, 0x100f);
            code(0x1010, 0x1017);
            check(currentProgram.getListing().getInstructionAt(a(0x1004)).isInDelaySlot(),
                "MIPS branch delay slot");
            function("delay_caller", 0x1000, 0x100f);
            function("delay_target", 0x1010, 0x1017);
            return;
        }
        code(0x1000, 0x100a);
        code(0x1010, 0x1017);
        code(0x1020, 0x1025);
        code(0x1030, 0x103a);
        // A branch has no fallthrough, so define the following bytes explicitly.
        code(0x1035, 0x103a);
        code(0x1040, 0x1045);
        code(0x1050, 0x1050);
        code(0x1060, 0x1062);
        code(0x1070, 0x1073);
        code(0x1074, 0x1076);
        code(0x1078, 0x1078);
        code(0x107a, 0x107b);
        function("flow_caller", 0x1000, 0x100a);
        function("flow_target", 0x1040, 0x1045);
        function("flow_jump", 0x1030, 0x103a);

        var overlay = currentProgram.getMemory().createInitializedBlock("flow_overlay", a(0x1000),
            4, (byte)0x90, monitor, true);
        check(new DisassembleCommand(overlay.getStart(),
            new AddressSet(overlay.getStart(), overlay.getEnd()), false)
            .applyTo(currentProgram, monitor), "overlay instructions");

        // Exercise the public API paths relevant to explicit no-fallthrough on a raw JMP.
        // Every route normalizes to an unset override; temporary flow overrides cannot
        // change the raw prototype against which setFallThrough compares null.
        Instruction jump = currentProgram.getListing().getInstructionAt(a(0x1030));
        for (FlowOverride override : new FlowOverride[] {FlowOverride.NONE, FlowOverride.CALL}) {
            jump.setFlowOverride(override);
            jump.setFallThrough(null);
            check(!jump.isFallThroughOverridden(), "raw terminal null target is normalized");
            jump.setFallThrough(a(0x103a));
            check(jump.isFallThroughOverridden(), "explicit target is supported");
            jump.setFallThrough(null);
            check(!jump.isFallThroughOverridden(), "target then null is normalized");
            jump.setFallThrough(a(0x103a));
            for (var reference : jump.getReferencesFrom()) {
                if (reference.getReferenceType() == RefType.FALL_THROUGH) {
                    currentProgram.getReferenceManager().delete(reference);
                }
            }
            check(!jump.isFallThroughOverridden(), "deleting target also clears flag");
        }
        jump.setFlowOverride(FlowOverride.NONE);
    }
}
