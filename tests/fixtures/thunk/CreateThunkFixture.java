import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;

public class CreateThunkFixture extends GhidraScript {
    private ProgramDB program;

    private Function function(String name, long offset, String hex) throws Exception {
        var address = program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        program.getMemory().setBytes(address, bytes);
        var body = new AddressSet(address, address.add(bytes.length - 1));
        if (!new DisassembleCommand(address, body, true).applyTo(program, monitor)) {
            throw new IllegalStateException("Cannot disassemble " + name);
        }
        var function = program.getFunctionManager().createFunction(name, address, body,
            name == null ? SourceType.DEFAULT : SourceType.USER_DEFINED);
        function.updateFunction("__cdecl", new ReturnParameterImpl(IntegerDataType.dataType, program),
            Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, false, SourceType.USER_DEFINED,
            new ParameterImpl("saved_value", IntegerDataType.dataType, program));
        function.setStackPurgeSize(0);
        return function;
    }

    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:32:default"));
        program = new ProgramDB(getScriptArgs()[0], language,
            language.getCompilerSpecByID(new CompilerSpecID("windows")), this);
        try {
            int tx = program.startTransaction("thunk fixture");
            try {
                var space = program.getAddressFactory().getDefaultAddressSpace();
                var block = program.getMemory().createInitializedBlock("code", space.getAddress(0x1000),
                    0x1000, (byte) 0xcc, monitor, false);
                block.setExecute(true);
                // The caller observes whether the selected callee consumes its stack argument.
                // This is the same instruction sequence used by the stack-purge regression.
                var caller = function("caller", 0x1000, "68111111116822222222e8f10000008b042483c404c3");
                caller.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                    true, SourceType.USER_DEFINED);
                function("source", 0x1100, "90c3");
                var dynamicTarget = function("dynamic_target", 0x1200, "c20400");
                dynamicTarget.updateFunction("__stdcall",
                    new ReturnParameterImpl(VoidDataType.dataType, program),
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, false, SourceType.IMPORTED,
                    new ParameterImpl("target_value", IntegerDataType.dataType, program));
                dynamicTarget.setStackPurgeSize(4);

                var customTarget = function("custom_target", 0x1300, "90c3");
                customTarget.updateFunction("__cdecl", new ReturnParameterImpl(LongLongDataType.dataType,
                    new VariableStorage(program, program.getRegister("EDX"), program.getRegister("EAX")), program),
                    Function.FunctionUpdateType.CUSTOM_STORAGE, false, SourceType.USER_DEFINED,
                    new ParameterImpl("in_register", IntegerDataType.dataType, program.getRegister("EAX"), program),
                    new ParameterImpl("on_stack", IntegerDataType.dataType, 4, program));
                var customSource = function("custom_source", 0x1400, "90c3");
                customSource.setParentNamespace(program.getSymbolTable()
                    .createNameSpace(null, "Saved", SourceType.USER_DEFINED));
                customSource.updateFunction("__cdecl", new ReturnParameterImpl(ShortDataType.dataType,
                    new VariableStorage(program, program.getRegister("AX")), program),
                    Function.FunctionUpdateType.CUSTOM_STORAGE, false, SourceType.USER_DEFINED,
                    new ParameterImpl("saved_register", IntegerDataType.dataType, program.getRegister("ECX"), program));
                customSource.setVarArgs(true);

                var middle = function("chain_middle", 0x1500, "90c3");
                middle.setThunkedFunction(dynamicTarget);
                function("chain_source", 0x1600, "90c3").setThunkedFunction(middle);
                function("target_link", 0x1700, "90c3").setThunkedFunction(customTarget);

                var methodTarget = function("method_target", 0x1800, "90c3");
                methodTarget.setParentNamespace(program.getSymbolTable()
                    .createClass(null, "Target", SourceType.USER_DEFINED));
                methodTarget.updateFunction("__thiscall", new ReturnParameterImpl(VoidDataType.dataType, program),
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, false, SourceType.USER_DEFINED,
                    new ParameterImpl("value", IntegerDataType.dataType, program));
                var methodSource = function("method_source", 0x1900, "90c3");
                methodSource.setParentNamespace(program.getSymbolTable()
                    .createClass(null, "Wrapper", SourceType.USER_DEFINED));
                for (int i = 0; i < 2; i++) {
                    var duplicate = function("ambiguous", 0x1a00 + 0x100 * i, "90c3");
                    duplicate.setParentNamespace(program.getSymbolTable()
                        .createNameSpace(null, "Scope" + i, SourceType.USER_DEFINED));
                }
                function(null, 0x1c00, "90c3");
                var external = program.getExternalManager().addExtFunction("library", "outside_target", null,
                    SourceType.IMPORTED).getFunction();
                external.setReturnType(VoidDataType.dataType, SourceType.IMPORTED);
            } finally {
                program.endTransaction(tx, true);
            }
            state.getProject().getProjectData().getRootFolder()
                .createFile(getScriptArgs()[0], program, monitor);
        } finally {
            program.release(this);
        }
    }
}
