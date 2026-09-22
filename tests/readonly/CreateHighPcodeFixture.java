import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;

public class CreateHighPcodeFixture extends GhidraScript {
    private Address address(Program program, long offset) {
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }

    private Function function(Program program, String name, long offset, DataType parameter,
            int... bytes) throws Exception {
        byte[] code = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++) code[i] = (byte) bytes[i];
        Address entry = address(program, offset);
        AddressSet body = new AddressSet(entry, entry.add(bytes.length - 1));
        program.getMemory().setBytes(entry, code);
        if (!new DisassembleCommand(entry, body, true).applyTo(program, monitor)) {
            throw new IllegalStateException("Cannot disassemble " + name);
        }
        Function function = program.getFunctionManager().createFunction(name, entry, body, SourceType.USER_DEFINED);
        function.setCallingConvention("__cdecl");
        function.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED);
        function.addParameter(new ParameterImpl("value", parameter, program), SourceType.USER_DEFINED);
        return function;
    }

    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:32:default"));
        var program = new ProgramDB(getScriptArgs()[0], language, language.getDefaultCompilerSpec(), this);
        try {
            int transaction = program.startTransaction("High P-code fixture");
            try {
                var code = program.getMemory().createInitializedBlock("code", address(program, 0x1000),
                    0x1000, (byte) 0, monitor, false);
                code.setExecute(true);
                // Both IMULT slots refer to one SSA value; EAX is reused for its result.
                function(program, "square", 0x1000, IntegerDataType.dataType,
                    0x8b, 0x44, 0x24, 0x04, 0x0f, 0xaf, 0xc0, 0xc3);
                // Two loop-carried values force MULTIEQUALs and a real data-dependency cycle.
                function(program, "sum_loop", 0x1040, IntegerDataType.dataType,
                    0x8b, 0x4c, 0x24, 0x04, 0x31, 0xc0, 0x85, 0xc9, 0x7e, 0x07,
                    0x01, 0xc8, 0x83, 0xe9, 0x01, 0x75, 0xf9, 0xc3);
                DataType pointer = new PointerDataType(IntegerDataType.dataType, 4, program.getDataTypeManager());
                // Memory reads/writes around a call preserve address-space operands and call roles.
                function(program, "memory_call", 0x1080, pointer,
                    0x53, 0x8b, 0x5c, 0x24, 0x08, 0x8b, 0x03, 0x83, 0xc0, 0x01, 0x89, 0x03,
                    0x53, 0xe8, 0x6e, 0x00, 0x00, 0x00, 0x83, 0xc4, 0x04, 0x8b, 0x03, 0x5b, 0xc3);
                function(program, "callee", 0x1100, pointer, 0xc3);
                StructureDataType pair = new StructureDataType("Pair", 0);
                pair.add(IntegerDataType.dataType, "left", null);
                pair.add(IntegerDataType.dataType, "right", null);
                // Two partial HighVariables share one parameter symbol.
                function(program, "pair_sum", 0x1140, pair,
                    0x8b, 0x44, 0x24, 0x04, 0x03, 0x44, 0x24, 0x08, 0xc3);
                // Passing a local's address lets CALL indirectly redefine its SSA value.
                function(program, "indirect_local", 0x1180, IntegerDataType.dataType,
                    0x55, 0x89, 0xe5, 0x83, 0xec, 0x04, 0x8b, 0x45, 0x08, 0x89, 0x45, 0xfc,
                    0x8d, 0x45, 0xfc, 0x50, 0xe8, 0x6b, 0xff, 0xff, 0xff, 0x83, 0xc4, 0x04,
                    0x8b, 0x45, 0xfc, 0xc9, 0xc3);
                function(program, "equate_bias", 0x11c0, IntegerDataType.dataType,
                    0x8b, 0x44, 0x24, 0x04, 0x05, 0x45, 0x23, 0x01, 0x00, 0xc3);
                program.getEquateTable().createEquate("BIAS", 0x12345)
                    .addReference(address(program, 0x11c4), 1);
            } finally {
                program.endTransaction(transaction, true);
            }
            state.getProject().getProjectData().getRootFolder().createFile(getScriptArgs()[0], program, monitor);
        } finally {
            program.release(this);
        }
    }
}
