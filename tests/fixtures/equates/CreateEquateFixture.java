import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.symbol.EquateManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.DynamicHash;
import ghidra.program.util.DefaultLanguageService;

public class CreateEquateFixture extends GhidraScript {
    private void instruction(Program program, int offset, int... bytes) throws Exception {
        Address address = program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
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
            int tx = program.startTransaction("equate fixture");
            try {
                var space = program.getAddressFactory().getDefaultAddressSpace();
                program.getMemory().createInitializedBlock("code", space.getAddress(0x1000),
                    0x1000, (byte) 0, monitor, false);
                instruction(program, 0x1000, 0xb8, 0x2a, 0, 0, 0);
                instruction(program, 0x1010, 0xb0, 0xff); // unsigned imm8 255
                instruction(program, 0x1020, 0xb8, 0xff, 0xff, 0xff, 0xff); // unsigned imm32
                instruction(program, 0x1030, 0x48, 0xb8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
                instruction(program, 0x1040, 0x83, 0xc0, 0xff); // signed, extended imm8 -1
                instruction(program, 0x1050, 0x48, 0xb8, 1, 0, 0, 0, 0, 0, 0x20, 0); // 2^53 + 1
                instruction(program, 0x1060, 0xb9, 0x2a, 0, 0, 0);
                instruction(program, 0x1070, 0xc8, 8, 0, 8); // ENTER: equal scalars on operands 0/1
                instruction(program, 0x1080, 0x8d, 0x44, 0x8b, 0x20); // two scalars on operand 1
                instruction(program, 0x1090, 0xc8, 0x20, 0, 8); // distinct operands
                instruction(program, 0x10a0, 0xb8, 0x2a, 0, 0, 0);
                instruction(program, 0x10b0, 0xb8, 0x2a, 0, 0, 0);
                instruction(program, 0x10c0, 0xb8, 0x2a, 0, 0, 0);
                program.getListing().createData(space.getAddress(0x1800), DWordDataType.dataType);

                var table = program.getEquateTable();
                var repeated = table.createEquate("NATIVE_REPEATED", 8);
                repeated.addReference(space.getAddress(0x1070), 0);
                repeated.addReference(space.getAddress(0x1070), 1);
                if (repeated.getReferenceCount() != 2) {
                    throw new IllegalStateException("Fixture requires separate repeated-value operand references");
                }
                // Existing native references can associate the instruction hash with
                // another operand. Reattaching at operand 1 would silently remove it.
                var collateral = table.createEquate("COLLATERAL", 42);
                collateral.addReference(space.getAddress(0x10a0), 0);
                if (collateral.getReferences()[0].getDynamicHashValue() == 0) {
                    throw new IllegalStateException("Fixture requires a dynamic hash");
                }
                // A direct varnode use whose operand cannot be determined.
                var dynamic = table.createEquate("DYNAMIC_ONLY", 99);
                for (int offset : new int[] {0x10b0, 0x10c0}) {
                    Address address = space.getAddress(offset);
                    long[] hashes = DynamicHash.calcConstantHash(program.getListing().getInstructionAt(address), 42);
                    if (hashes.length != 1) throw new IllegalStateException("Fixture requires one hash");
                    dynamic.addReference(hashes[0], address);
                }
                if (dynamic.getReferences()[0].getOpIndex() != -1) {
                    throw new IllegalStateException("Fixture requires a dynamic-only reference");
                }
                var enumeration = new EnumDataType("EquateFixtureModes", 4);
                enumeration.add("READ_MODE", 42);
                var installed = program.getDataTypeManager().addDataType(enumeration, null);
                table.createEquate(EquateManager.formatNameForEquate(installed.getUniversalID(), 42), 42);
            } finally {
                program.endTransaction(tx, true);
            }
            state.getProject().getProjectData().getRootFolder().createFile(getScriptArgs()[0], program, monitor);
        } finally {
            program.release(this);
        }
    }
}
