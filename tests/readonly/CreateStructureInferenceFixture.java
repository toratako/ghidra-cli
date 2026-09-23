import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;

/** Small explicit x86 functions independent of the host compiler and ABI. */
public class CreateStructureInferenceFixture extends GhidraScript {
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
        if (parameter != null) function.addParameter(new ParameterImpl("ctx", parameter, program), SourceType.USER_DEFINED);
        return function;
    }

    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:32:default"));
        var program = new ProgramDB(getScriptArgs()[0], language, language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("structure inference fixture");
            try {
                var block = program.getMemory().createInitializedBlock("code", address(program, 0x1000),
                    0x1000, (byte) 0, monitor, false);
                block.setExecute(true);
                var dtm = program.getDataTypeManager();
                DataType voidPointer = new PointerDataType(VoidDataType.dataType, 4, dtm);
                DataType charPointer = new PointerDataType(CharDataType.dataType, 4, dtm);
                int[] access = {0x8b, 0x4c, 0x24, 0x04, 0x8b, 0x41, 0x10,
                    0x8b, 0x54, 0x24, 0x08, 0x89, 0x51, 0x18, 0xc3};
                Function raw = function(program, "recover", 0x1000, voidPointer, access);
                raw.addParameter(new ParameterImpl("buffer", charPointer, program), SourceType.USER_DEFINED);
                Function integer = function(program, "integer_root", 0x1040, UnsignedIntegerDataType.dataType, access);
                integer.addParameter(new ParameterImpl("buffer", charPointer, program), SourceType.USER_DEFINED);
                StructureDataType existing = new StructureDataType("Existing", 0x40, dtm);
                existing.replaceAtOffset(0x10, IntegerDataType.dataType, 4, "count", "preserve me");
                existing.replaceAtOffset(0x24, IntegerDataType.dataType, 4, "unobserved", null);
                DataType registered = dtm.addDataType(existing, DataTypeConflictHandler.DEFAULT_HANDLER);
                Function typed = function(program, "typed_root", 0x1080, new PointerDataType(registered, 4, dtm), access);
                typed.addParameter(new ParameterImpl("buffer", charPointer, program), SourceType.USER_DEFINED);
                function(program, "no_access", 0x10c0, voidPointer, 0x8b, 0x44, 0x24, 0x04, 0xc3);
                // A variable subscript must not be converted into a fixed field offset by the CLI.
                Function indexed = function(program, "indexed", 0x1100, voidPointer,
                    0x8b, 0x4c, 0x24, 0x04, 0x8b, 0x54, 0x24, 0x08, 0x8b, 0x04, 0x91, 0xc3);
                indexed.addParameter(new ParameterImpl("index", IntegerDataType.dataType, program), SourceType.USER_DEFINED);
                // Preserve native evidence of different widths even if the helper picks one layout.
                function(program, "overlap", 0x1140, voidPointer,
                    0x8b, 0x4c, 0x24, 0x04, 0x8b, 0x41, 0x10, 0xc6, 0x41, 0x10, 0x01, 0xc3);
                StructureDataType pair = new StructureDataType("Pair", 0);
                pair.add(IntegerDataType.dataType, "left", null);
                pair.add(IntegerDataType.dataType, "right", null);
                function(program, "partial", 0x1180, pair,
                    0x8b, 0x44, 0x24, 0x04, 0x03, 0x44, 0x24, 0x08, 0xc3);
                // This root must never trigger class creation or namespace reassignment.
                Function method = function(program, "method", 0x11c0, null, 0x8b, 0x41, 0x10, 0xc3);
                method.setParentNamespace(program.getSymbolTable().createClass(
                    program.getGlobalNamespace(), "Holder", SourceType.USER_DEFINED));
                method.setCallingConvention("__thiscall");
                // A native decompilation failure is distinct from an empty inference.
                program.getExternalManager().addExtFunction("library", "outside", null, SourceType.IMPORTED);
            } finally {
                program.endTransaction(tx, true);
            }
            state.getProject().getProjectData().getRootFolder().createFile(getScriptArgs()[0], program, monitor);
        } finally {
            program.release(this);
        }
    }
}
