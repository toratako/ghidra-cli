import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.*;
import ghidra.program.util.DefaultLanguageService;

public class CreateNamespaceFixture extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:32:default"));
        var program = new ProgramDB(getScriptArgs()[0], language,
            language.getCompilerSpecByID(new CompilerSpecID("windows")), this);
        try {
            int transaction = program.startTransaction("namespace fixture");
            try {
                var space = program.getAddressFactory().getDefaultAddressSpace();
                var start = space.getAddress(0x1000);
                program.getMemory().createInitializedBlock("fixture", start,
                    0x100, (byte) 0xc3, monitor, false);
                var table = program.getSymbolTable();
                var global = program.getGlobalNamespace();
                var left = table.createNameSpace(global, "left", SourceType.USER_DEFINED);
                var right = table.createNameSpace(global, "right", SourceType.USER_DEFINED);
                var first = table.createLabel(space.getAddress(0x1010), "shared", left, SourceType.USER_DEFINED);
                table.createLabel(space.getAddress(0x1010), "shared", right, SourceType.USER_DEFINED);
                table.createLabel(space.getAddress(0x1030), "first_label", SourceType.USER_DEFINED);
                table.createLabel(space.getAddress(0x1030), "second_label", SourceType.USER_DEFINED);
                var refs = program.getReferenceManager();
                var reference = refs.addMemoryReference(start, first.getAddress(), RefType.DATA,
                    SourceType.USER_DEFINED, 0);
                refs.setAssociation(first, reference);
                refs.addMemoryReference(start.add(1), space.getAddress(0x1090), RefType.DATA,
                    SourceType.USER_DEFINED, 0);
                for (int i = 0; i < 2; i++) {
                    var entry = space.getAddress(0x1040 + i * 0x10);
                    var function = program.getFunctionManager().createFunction(
                        i == 0 ? "method" : "plain", entry, new AddressSet(entry), SourceType.USER_DEFINED);
                    function.setCallingConvention(i == 0 ? "__thiscall" : "__cdecl");
                    function.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED);
                    function.addParameter(new ParameterImpl("value", IntegerDataType.dataType,
                        4, program), SourceType.USER_DEFINED);
                }
                table.createLabel(space.getAddress(0x1040), "function_alias", SourceType.USER_DEFINED);
                program.getExternalManager().addExtLocation("fixture_library", "outside_label",
                    null, SourceType.USER_DEFINED);
            } finally {
                program.endTransaction(transaction, true);
            }
            state.getProject().getProjectData().getRootFolder()
                .createFile(getScriptArgs()[0], program, monitor);
        } finally {
            program.release(this);
        }
    }
}
