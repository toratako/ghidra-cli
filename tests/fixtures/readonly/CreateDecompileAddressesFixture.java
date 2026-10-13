import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;

public class CreateDecompileAddressesFixture extends GhidraScript {
    private Address address(Program program, long offset) {
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }

    private AddressSet code(Program program, Address start, int... bytes) throws Exception {
        byte[] encoded = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++) encoded[i] = (byte) bytes[i];
        program.getMemory().setBytes(start, encoded);
        var body = new AddressSet(start, start.add(bytes.length - 1));
        if (!new DisassembleCommand(start, body, true).applyTo(program, monitor)) {
            throw new IllegalStateException("Could not disassemble address fixture at " + start);
        }
        return body;
    }

    private Function function(Program program, String name, AddressSet body, DataType... parameters)
            throws Exception {
        var function = program.getFunctionManager().createFunction(name, body.getMinAddress(), body,
            SourceType.USER_DEFINED);
        function.setCallingConvention("__cdecl");
        function.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED);
        for (int i = 0; i < parameters.length; i++) {
            function.addParameter(new ParameterImpl("input_value_" + i, parameters[i], program),
                SourceType.USER_DEFINED);
        }
        return function;
    }

    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:32:default"));
        var program = new ProgramDB(getScriptArgs()[0], language, language.getDefaultCompilerSpec(), this);
        try {
            int transaction = program.startTransaction("decompiler line-address fixture");
            try {
                var text = program.getMemory().createInitializedBlock("code", address(program, 0x1000),
                    0x800, (byte) 0, monitor, false);
                text.setExecute(true);

                // push input; call 0x1100; discard argument; add eax,7; ret.
                // Several call tokens share 0x1004; the return combines 0x100c and 0x100f.
                var caller = code(program, address(program, 0x1000),
                    0xff, 0x74, 0x24, 0x04, 0xe8, 0xf7, 0x00, 0x00, 0x00,
                    0x83, 0xc4, 0x04, 0x83, 0xc0, 0x07, 0xc3);
                function(program, "address-caller", caller, IntegerDataType.dataType);
                program.getListing().setComment(address(program, 0x1004), CodeUnit.PRE_COMMENT,
                    "Japanese 日本語\nsecond comment line");
                var sink = code(program, address(program, 0x1100),
                    0x8b, 0x44, 0x24, 0x04, 0x83, 0xc0, 0x01, 0xc3);
                function(program, "address-sink", sink, IntegerDataType.dataType);

                // Pass eight array elements to force a wrapped call at the normal print width.
                // LOADs occur at 0x1204..0x1219, CALL at 0x121b, RETURN at 0x1223.
                var wrapped = code(program, address(program, 0x1200),
                    0x8b, 0x44, 0x24, 0x04,
                    0xff, 0x70, 0x1c, 0xff, 0x70, 0x18, 0xff, 0x70, 0x14,
                    0xff, 0x70, 0x10, 0xff, 0x70, 0x0c, 0xff, 0x70, 0x08,
                    0xff, 0x70, 0x04, 0xff, 0x30,
                    0xe8, 0xe0, 0x01, 0x00, 0x00, 0x83, 0xc4, 0x20, 0xc3);
                function(program, "wrapped_arguments", wrapped,
                    new PointerDataType(IntegerDataType.dataType, 4, program.getDataTypeManager()));
                var many = code(program, address(program, 0x1400),
                    0x8b, 0x44, 0x24, 0x04, 0x03, 0x44, 0x24, 0x08,
                    0x03, 0x44, 0x24, 0x0c, 0x03, 0x44, 0x24, 0x10,
                    0x03, 0x44, 0x24, 0x14, 0x03, 0x44, 0x24, 0x18,
                    0x03, 0x44, 0x24, 0x1c, 0x03, 0x44, 0x24, 0x20, 0xc3);
                function(program, "address_sink_with_eight_arguments_and_a_wrapped_call", many,
                    IntegerDataType.dataType, IntegerDataType.dataType, IntegerDataType.dataType,
                    IntegerDataType.dataType, IntegerDataType.dataType, IntegerDataType.dataType,
                    IntegerDataType.dataType, IntegerDataType.dataType);

                // The source expression spans disconnected body ranges, never their gap.
                var disjoint = code(program, address(program, 0x1600),
                    0x8b, 0x44, 0x24, 0x04, 0x83, 0xc0, 0x05,
                    0xe9, 0x74, 0x00, 0x00, 0x00);
                disjoint.add(code(program, address(program, 0x1680), 0xc3));
                function(program, "disjoint_sum", disjoint, IntegerDataType.dataType);

                // Same offsets as the ordinary caller, in a distinct address space.
                var overlay = program.getMemory().createInitializedBlock("address_overlay",
                    address(program, 0x1000), 0x20, (byte) 0, monitor, true);
                overlay.setExecute(true);
                var overlayBody = code(program, overlay.getStart(),
                    0x8b, 0x44, 0x24, 0x04, 0x83, 0xc0, 0x05, 0xc3);
                function(program, "overlay_sum", overlayBody, IntegerDataType.dataType);
            } finally {
                program.endTransaction(transaction, true);
            }
            state.getProject().getProjectData().getRootFolder().createFile(getScriptArgs()[0], program, monitor);
        } finally {
            program.release(this);
        }
    }
}
