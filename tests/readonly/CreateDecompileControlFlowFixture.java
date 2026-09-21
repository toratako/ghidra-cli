import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;

public class CreateDecompileControlFlowFixture extends GhidraScript {
    private Address address(Program program, long offset) {
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }

    private void code(Program program, long offset, int... bytes) throws Exception {
        byte[] encoded = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++) encoded[i] = (byte) bytes[i];
        var start = address(program, offset);
        program.getMemory().setBytes(start, encoded);
        if (!new DisassembleCommand(start, new AddressSet(start, start.add(bytes.length - 1)), true)
                .applyTo(program, monitor)) {
            throw new IllegalStateException("Could not disassemble fixture at " + start);
        }
    }

    private Function function(Program program, String name, long start, long end, DataType parameter)
            throws Exception {
        var entry = address(program, start);
        var function = program.getFunctionManager().createFunction(name, entry,
            new AddressSet(entry, address(program, end)), SourceType.USER_DEFINED);
        function.setCallingConvention("__cdecl");
        function.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED);
        function.addParameter(new ParameterImpl("value", parameter, program), SourceType.USER_DEFINED);
        return function;
    }

    private void jumpTable(Program program, long offset, long... destinations) throws Exception {
        for (int i = 0; i < destinations.length; i++) {
            var slot = address(program, offset + i * 4);
            program.getMemory().setInt(slot, (int) destinations[i]);
            program.getListing().createData(slot, new PointerDataType(null, 4, program.getDataTypeManager()));
        }
    }

    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:32:default"));
        var program = new ProgramDB(getScriptArgs()[0], language, language.getDefaultCompilerSpec(), this);
        try {
            int transaction = program.startTransaction("decompiler control-flow fixture");
            try {
                var text = program.getMemory().createInitializedBlock("code", address(program, 0x1000),
                    0x1000, (byte) 0, monitor, false);
                text.setExecute(true);
                var data = program.getMemory().createInitializedBlock("tables", address(program, 0x2000),
                    0x100, (byte) 0, monitor, false);
                data.setWrite(false);

                code(program, 0x1000, 0x8b, 0x44, 0x24, 0x04, 0x83, 0xc0, 0x05, 0xc3);
                // An unreachable instruction is deliberately included in the body.
                // The listing has two blocks, but the returned HighFunction has one.
                code(program, 0x1020, 0xc3);
                var straight = function(program, "straight", 0x1000, 0x1020, IntegerDataType.dataType);
                var blocks = new BasicBlockModel(program).getCodeBlocksContaining(straight.getBody(), monitor);
                int count = 0;
                while (blocks.hasNext()) { blocks.next(); count++; }
                if (count != 2) throw new IllegalStateException("Expected two listing blocks, got " + count);

                // if (value > 0) return value * 3; else return value - 5;
                code(program, 0x1040, 0x8b, 0x44, 0x24, 0x04, 0x85, 0xc0, 0x7e, 0x04,
                    0x8d, 0x04, 0x40, 0xc3, 0x83, 0xe8, 0x05, 0xc3);
                function(program, "branching", 0x1040, 0x104f, IntegerDataType.dataType);

                // switch (value) with labels -2, -1, 0, 1, and a repeated destination.
                code(program, 0x1100, 0x8b, 0x44, 0x24, 0x04, 0x83, 0xc0, 0x02,
                    0x83, 0xf8, 0x03, 0x77, 0x24, 0xff, 0x24, 0x85, 0x00, 0x20, 0x00, 0x00);
                code(program, 0x1130, 0xb8, 0xff, 0xff, 0xff, 0xff, 0xc3);
                code(program, 0x1140, 0xb8, 0x0b, 0x00, 0x00, 0x00, 0xc3);
                code(program, 0x1150, 0xb8, 0x16, 0x00, 0x00, 0x00, 0xc3);
                code(program, 0x1160, 0xb8, 0x21, 0x00, 0x00, 0x00, 0xc3);
                jumpTable(program, 0x2000, 0x1140, 0x1150, 0x1160, 0x1150);
                function(program, "signed_switch", 0x1100, 0x1165, IntegerDataType.dataType);

                // Unsigned high-bit labels exercise the Java API's raw int representation.
                code(program, 0x1200, 0x8b, 0x44, 0x24, 0x04, 0x05, 0x00, 0x00, 0x00, 0x80,
                    0x83, 0xf8, 0x03, 0x77, 0x22, 0xff, 0x24, 0x85, 0x20, 0x20, 0x00, 0x00);
                code(program, 0x1230, 0xb8, 0xff, 0xff, 0xff, 0xff, 0xc3);
                code(program, 0x1240, 0xb8, 0x0b, 0x00, 0x00, 0x00, 0xc3);
                code(program, 0x1250, 0xb8, 0x16, 0x00, 0x00, 0x00, 0xc3);
                code(program, 0x1260, 0xb8, 0x21, 0x00, 0x00, 0x00, 0xc3);
                jumpTable(program, 0x2020, 0x1240, 0x1250, 0x1260, 0x1250);
                function(program, "unsigned_switch", 0x1200, 0x1265, UnsignedIntegerDataType.dataType);
            } finally {
                program.endTransaction(transaction, true);
            }
            state.getProject().getProjectData().getRootFolder().createFile(getScriptArgs()[0], program, monitor);
        } finally {
            program.release(this);
        }
    }
}
