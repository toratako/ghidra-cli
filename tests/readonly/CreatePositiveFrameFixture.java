import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;

public class CreatePositiveFrameFixture extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("8051:BE:16:default"));
        var program = new ProgramDB(getScriptArgs()[0], language,
            language.getCompilerSpecByID(new CompilerSpecID("default")), this);
        try {
            int tx = program.startTransaction("positive frame fixture");
            try {
                var entry = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
                var function = program.getFunctionManager().createFunction("positive_frame", entry,
                    new AddressSet(entry, entry), SourceType.USER_DEFINED);
                function.updateFunction("__stdcall",
                    new ReturnParameterImpl(VoidDataType.dataType, program),
                    FunctionUpdateType.CUSTOM_STORAGE, false, SourceType.USER_DEFINED,
                    new ParameterImpl("first", ByteDataType.dataType, -4, program),
                    new ParameterImpl("second", ByteDataType.dataType, -6, program),
                    new ParameterImpl("split", WordDataType.dataType,
                        new VariableStorage(program,
                            new Varnode(program.getRegister("ACC").getAddress(), 1),
                            new Varnode(program.getAddressFactory().getStackSpace().getAddress(-8), 1)),
                        program));
                function.addLocalVariable(new LocalVariableImpl("local", ByteDataType.dataType,
                    4, program), SourceType.USER_DEFINED);
                function.getStackFrame().setReturnAddressOffset(-2);
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
