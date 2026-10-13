
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;
public class CreateAnalysisModesFixture extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:32:default"));
        var program = new ProgramDB(getScriptArgs()[0], language,
            language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("analysis modes fixture");
            try {
                for (int i = 1; i <= 4; i++) {
                    var start = program.getAddressFactory().getDefaultAddressSpace().getAddress(i * 0x1000);
                    program.getMemory().createInitializedBlock("text_" + i, start,
                        0x100, (byte) 0, monitor, false);
                    program.getMemory().setBytes(start,
                        "The quick brown fox\0".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
                }
                program.getMemory().createInitializedBlock("overlay",
                    program.getAddressFactory().getDefaultAddressSpace().getAddress(0x6000),
                    0x100, (byte) 0, monitor, true);
            } finally { program.endTransaction(tx, true); }
            state.getProject().getProjectData().getRootFolder()
                .createFile(getScriptArgs()[0], program, monitor);
        } finally { program.release(this); }
    }
}
