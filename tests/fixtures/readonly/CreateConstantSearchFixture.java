import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;

public class CreateConstantSearchFixture extends GhidraScript {
    private void instruction(Program program, Address address, int... bytes) throws Exception {
        byte[] encoded = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++) encoded[i] = (byte) bytes[i];
        program.getMemory().setBytes(address, encoded);
        if (!new DisassembleCommand(address, new AddressSet(address, address.add(bytes.length - 1)), false)
                .applyTo(program, monitor)) {
            throw new IllegalStateException("Could not disassemble fixture at " + address);
        }
    }

    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
        var program = new ProgramDB(getScriptArgs()[0], language, language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("constant search fixture");
            try {
                var space = program.getAddressFactory().getDefaultAddressSpace();
                program.getMemory().createInitializedBlock("code", space.getAddress(0x1000),
                    0x1000, (byte) 0, monitor, false);
                program.getMemory().createInitializedBlock("data", space.getAddress(0x2000),
                    0x100, (byte) 0, monitor, false);
                instruction(program, space.getAddress(0x1000), 0xb8, 0xff, 0xff, 0xff, 0xff);
                instruction(program, space.getAddress(0x1010), 0xb0, 0xff);
                instruction(program, space.getAddress(0x1020), 0x66, 0xb8, 0xff, 0xff);
                instruction(program, space.getAddress(0x1030), 0x48, 0xb8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
                instruction(program, space.getAddress(0x1040), 0xb8, 0x00, 0x00, 0x00, 0x80);
                instruction(program, space.getAddress(0x1050), 0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80);
                // Neighboring values above binary64's exact-integer range.
                instruction(program, space.getAddress(0x1060), 0x48, 0xb8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00);
                instruction(program, space.getAddress(0x1070), 0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00);
                instruction(program, space.getAddress(0x1080), 0xb9, 0x10, 0x00, 0x00, 0x00);
                instruction(program, space.getAddress(0x1090), 0xba, 0x20, 0x00, 0x00, 0x00);
                instruction(program, space.getAddress(0x10a0), 0xbb, 0x30, 0x00, 0x00, 0x00);
                instruction(program, space.getAddress(0x10b0), 0x8b, 0x43, 0x20); // [RBX + 0x20]
                instruction(program, space.getAddress(0x10c0), 0x83, 0xc0, 0xff); // sign-extended imm8
                instruction(program, space.getAddress(0x10d0), 0xc8, 0x08, 0x00, 0x08); // two matching operands
                instruction(program, space.getAddress(0x10e0), 0x8d, 0x44, 0x8b, 0x20); // scale and displacement
                instruction(program, space.getAddress(0x1100), 0xe8, 0xfb, 0x0e, 0x00, 0x00); // CALL Address 0x2000
                program.getFunctionManager().createFunction("constant_cases", space.getAddress(0x1000),
                    new AddressSet(space.getAddress(0x1000), space.getAddress(0x1104)), SourceType.USER_DEFINED);
                program.getSymbolTable().createLabel(space.getAddress(0x1080), "range_start", SourceType.USER_DEFINED);
                program.getSymbolTable().createLabel(space.getAddress(0x10a0), "range_end", SourceType.USER_DEFINED);

                // These bytes must remain excluded even when they encode an instruction or integer.
                program.getMemory().setBytes(space.getAddress(0x1200),
                    new byte[] {(byte) 0xb8, 0x10, 0x32, 0x54, 0x76});
                program.getMemory().setBytes(space.getAddress(0x2000), new byte[] {0x10, 0x32, 0x54, 0x76});
                program.getListing().createData(space.getAddress(0x2000), DWordDataType.dataType);
                program.getMemory().setBytes(space.getAddress(0x2010),
                    new byte[] {-1, -1, -1, -1, -1, -1, -1, -1});
                program.getListing().createData(space.getAddress(0x2010), QWordDataType.dataType);
                program.getMemory().setBytes(space.getAddress(0x2020),
                    new byte[] {-1, -1, -1, -1, -1, -1, -1, -1});

                var overlay = program.getMemory().createInitializedBlock("constant_overlay",
                    space.getAddress(0x1000), 0x20, (byte) 0, monitor, true);
                instruction(program, overlay.getStart(), 0xb8, 0xff, 0xff, 0xff, 0xff);
            } finally {
                program.endTransaction(tx, true);
            }
            state.getProject().getProjectData().getRootFolder().createFile(getScriptArgs()[0], program, monitor);
        } finally {
            program.release(this);
        }
    }
}
