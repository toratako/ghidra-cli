import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;

public class CreateCfgFixture extends GhidraScript {
    private Address address(Program program, long offset) {
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }

    private void code(Program program, long offset, int... bytes) throws Exception {
        byte[] encoded = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++) encoded[i] = (byte) bytes[i];
        Address start = address(program, offset);
        program.getMemory().setBytes(start, encoded);
        if (!new DisassembleCommand(start, new AddressSet(start, start.add(bytes.length - 1)), true)
                .applyTo(program, monitor)) {
            throw new IllegalStateException("Could not disassemble CFG fixture at " + start);
        }
    }

    private void function(Program program, String name, long... ranges) throws Exception {
        AddressSet body = new AddressSet();
        for (int i = 0; i < ranges.length; i += 2) {
            body.add(address(program, ranges[i]), address(program, ranges[i + 1]));
        }
        program.getFunctionManager().createFunction(name, address(program, ranges[0]), body,
            SourceType.USER_DEFINED);
    }

    public void run() throws Exception {
        boolean mips = getScriptArgs().length > 1 && getScriptArgs()[1].equals("mips");
        var language = DefaultLanguageService.getLanguageService().getLanguage(
            new LanguageID(mips ? "MIPS:BE:32:default" : "x86:LE:32:default"));
        var program = new ProgramDB(getScriptArgs()[0], language, language.getDefaultCompilerSpec(), this);
        try {
            int transaction = program.startTransaction("instruction CFG fixture");
            try {
                var text = program.getMemory().createInitializedBlock("code", address(program, 0x1000),
                    0x1100, (byte) 0, monitor, false);
                text.setExecute(true);
                if (mips) {
                    // beq a0,zero,0x1010; addiu v0,zero,1 (delay slot).
                    code(program, 0x1000, 0x10, 0x80, 0, 3, 0x24, 2, 0, 1);
                    code(program, 0x1008, 0x03, 0xe0, 0, 8, 0, 0, 0, 0);
                    code(program, 0x1010, 0x03, 0xe0, 0, 8, 0x24, 2, 0, 2);
                    // Deliberately exclude the branch's delay slot from the body.
                    function(program, "delay", 0x1000, 0x1003, 0x1008, 0x1017);
                    if (!program.getListing().getInstructionAt(address(program, 0x1004)).isInDelaySlot()) {
                        throw new IllegalStateException("Expected branch delay slot");
                    }
                } else {
                    // Both arms converge on the final add/ret block.
                    code(program, 0x1000, 0x85, 0xc0, 0x74, 7, 0xb8, 1, 0, 0, 0, 0xeb, 5,
                        0xb8, 2, 0, 0, 0, 0x83, 0xc0, 3, 0xc3);
                    function(program, "diamond", 0x1000, 0x1013);
                    code(program, 0x1100, 0x31, 0xc0, 0x40, 0x83, 0xf8, 5, 0x75, 0xfa, 0xc3);
                    function(program, "looping", 0x1100, 0x1108);
                    // The unresolved register call is in the middle of a native block.
                    code(program, 0x1200, 0xff, 0xd0, 0xb8, 3, 0, 0, 0,
                        0xe8, 0xf4, 1, 0, 0, 0xc3);
                    function(program, "caller", 0x1200, 0x120c);
                    code(program, 0x1250, 0xff, 0x15, 0, 0x20, 0, 0, 0x90, 0xc3);
                    function(program, "pointer_caller", 0x1250, 0x1257);
                    program.getMemory().setInt(address(program, 0x2000), 0x1400);
                    program.getListing().createData(address(program, 0x2000),
                        new PointerDataType(null, 4, program.getDataTypeManager()));
                    program.getReferenceManager().addMemoryReference(address(program, 0x2000),
                        address(program, 0x1400), RefType.DATA, SourceType.USER_DEFINED, 0);
                    code(program, 0x1280, 0xff, 0xd0, 0x90, 0xc3);
                    function(program, "external_caller", 0x1280, 0x1283);
                    var external = program.getExternalManager().addExtFunction("fixture", "external_target",
                        null, SourceType.USER_DEFINED);
                    program.getReferenceManager().addExternalReference(address(program, 0x1280), 0,
                        external, SourceType.USER_DEFINED, RefType.COMPUTED_CALL);
                    code(program, 0x1300, 0xe9, 0xfb, 0, 0, 0);
                    function(program, "outside", 0x1300, 0x1304);
                    code(program, 0x1350, 0xe9, 0xab, 0x0a, 0, 0);
                    function(program, "missing", 0x1350, 0x1354);
                    code(program, 0x1380, 0xff, 0xe0);
                    function(program, "unresolved", 0x1380, 0x1381);
                    code(program, 0x1400, 0xc3);
                    function(program, "target", 0x1400, 0x1400);
                    code(program, 0x1500, 0x90, 0x90, 0x90, 0xc3);
                    function(program, "disjoint", 0x1500, 0x1500, 0x1502, 0x1503);
                    code(program, 0x1600, 0xc3);
                    code(program, 0x1620, 0xc3);
                    function(program, "unreachable", 0x1600, 0x1600, 0x1620, 0x1620);
                    code(program, 0x1700, 0xe8, 0xfb, 0xfc, 0xff, 0xff, 0xc3);
                    function(program, "override_branch", 0x1700, 0x1705);
                    program.getListing().getInstructionAt(address(program, 0x1700))
                        .setFlowOverride(FlowOverride.BRANCH);
                    code(program, 0x1720, 0xe8, 0xdb, 0xfc, 0xff, 0xff, 0xc3);
                    function(program, "terminal_call", 0x1720, 0x1725);
                    program.getListing().getInstructionAt(address(program, 0x1720))
                        .setFlowOverride(FlowOverride.CALL_RETURN);
                    code(program, 0x1740, 0x90, 0xc3);
                    code(program, 0x1750, 0xc3);
                    function(program, "redirected", 0x1740, 0x1741, 0x1750, 0x1750);
                    program.getListing().getInstructionAt(address(program, 0x1740))
                        .setFallThrough(address(program, 0x1750));
                }
            } finally {
                program.endTransaction(transaction, true);
            }
            state.getProject().getProjectData().getRootFolder().createFile(getScriptArgs()[0], program, monitor);
        } finally {
            program.release(this);
        }
    }
}
