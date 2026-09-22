import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;

public class CreateSignatureDetailsFixture extends GhidraScript {
    private ProgramDB program;

    private Function function(String name, long offset) throws Exception {
        var address = program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
        return program.getFunctionManager().createFunction(name, address,
            new AddressSet(address, address), SourceType.USER_DEFINED);
    }

    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:32:default"));
        program = new ProgramDB(getScriptArgs()[0], language,
            language.getCompilerSpecByID(new CompilerSpecID(getScriptArgs()[1])), this);
        try {
            int tx = program.startTransaction("signature details fixture");
            try {
                // No instructions or analysis: signature inspection must stand on its own.
                function("unknown", 0x1000);
                var plain = function("plain", 0x1100);
                plain.updateFunction("__cdecl",
                    new ReturnParameterImpl(IntegerDataType.dataType, program),
                    FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, false, SourceType.USER_DEFINED,
                    new ParameterImpl("second", IntegerDataType.dataType, program),
                    new ParameterImpl("first", IntegerDataType.dataType, program));
                plain.moveParameter(1, 0);
                plain.setVarArgs(true);
                plain.setStackPurgeSize(4);
                plain.addLocalVariable(new LocalVariableImpl("buffer", IntegerDataType.dataType,
                    -16, program), SourceType.USER_DEFINED);
                plain.addLocalVariable(new LocalVariableImpl("flag", ShortDataType.dataType,
                    -4, program), SourceType.ANALYSIS);
                plain.addLocalVariable(new LocalVariableImpl("scratch", 0, IntegerDataType.dataType,
                    program.getRegister("ECX"), program), SourceType.USER_DEFINED);
                plain.getStackFrame().setReturnAddressOffset(8);

                var result = new StructureDataType(new CategoryPath("/Recovered"), "Result", 16);
                var indirect = function("indirect", 0x1200);
                indirect.updateFunction("__cdecl", new ReturnParameterImpl(result, program),
                    FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, false, SourceType.IMPORTED,
                    new ParameterImpl("value", IntegerDataType.dataType, program));

                var method = function("method", 0x1300);
                method.updateFunction("__thiscall", new ReturnParameterImpl(VoidDataType.dataType, program),
                    FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, false, SourceType.USER_DEFINED,
                    new ParameterImpl("value", IntegerDataType.dataType, program));

                var custom = function("custom", 0x1400);
                custom.updateFunction("__cdecl", new ReturnParameterImpl(LongLongDataType.dataType,
                    new VariableStorage(program, program.getRegister("EDX"), program.getRegister("EAX")), program),
                    FunctionUpdateType.CUSTOM_STORAGE, false, SourceType.USER_DEFINED,
                    new ParameterImpl("input", IntegerDataType.dataType, program.getRegister("EAX"), program),
                    new ParameterImpl("on_stack", IntegerDataType.dataType, 4, program));
                custom.addLocalVariable(new LocalVariableImpl("custom_local", IntegerDataType.dataType,
                    -12, program), SourceType.IMPORTED);

                var unassigned = function("unassigned", 0x1500);
                unassigned.updateFunction("__cdecl",
                    new ReturnParameterImpl(IntegerDataType.dataType, VariableStorage.UNASSIGNED_STORAGE, program),
                    FunctionUpdateType.CUSTOM_STORAGE, false, SourceType.USER_DEFINED);

                var plainThunk = function("plain_thunk", 0x1600);
                plainThunk.setThunkedFunction(plain);
                function("chained_thunk", 0x1800).setThunkedFunction(plainThunk);
                var methodThunk = function("method_thunk", 0x1700);
                methodThunk.setParentNamespace(program.getSymbolTable().createClass(null, "Wrapper", SourceType.USER_DEFINED));
                methodThunk.setThunkedFunction(method);
                var external = program.getExternalManager()
                    .addExtFunction("library", "outside", null, SourceType.IMPORTED).getFunction();
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
