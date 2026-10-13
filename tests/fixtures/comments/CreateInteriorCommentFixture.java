
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
public class CreateInteriorCommentFixture extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
        var program = new ProgramDB(getScriptArgs()[0], language,
            language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("comment fixture");
            try {
                var start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
                var memory = program.getMemory();
                memory.createInitializedBlock("code", start, 16, (byte) 0, monitor, false);
                memory.setBytes(start, new byte[] {0x66, (byte) 0x90, (byte) 0xc3});
                program.getListing().createData(start.add(8), DWordDataType.dataType);
                program.getExternalManager().addExtFunction("comment_library",
                    "comment_external", null, SourceType.USER_DEFINED);
            } finally { program.endTransaction(tx, true); }
            state.getProject().getProjectData().getRootFolder()
                .createFile(getScriptArgs()[0], program, monitor);
        } finally { program.release(this); }
    }
}
