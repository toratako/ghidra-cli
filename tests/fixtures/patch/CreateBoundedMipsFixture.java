
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;
public class CreateBoundedMipsFixture extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("MIPS:BE:32:default"));
        var program = new ProgramDB(getScriptArgs()[0], language,
            language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("bounded MIPS fixture");
            try {
                byte[] bytes = {
                    0x10, 0, 0, 3, 0, 0, 0, 0, // branch to 0x1010, NOP delay slot
                    0, 0, 0, 0, 0, 0, 0, 0,    // unreachable bytes
                    3, (byte) 0xe0, 0, 8, 0, 0, 0, 0 // jr ra, NOP delay slot
                };
                var start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
                program.getMemory().createInitializedBlock("code", start,
                    new java.io.ByteArrayInputStream(bytes), bytes.length, monitor, false).setExecute(true);
            } finally { program.endTransaction(tx, true); }
            state.getProject().getProjectData().getRootFolder().createFile(getScriptArgs()[0], program, monitor);
        } finally { program.release(this); }
    }
}
