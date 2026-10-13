
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;
public class CreateInstructionSearchFixture extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(args[1]));
        var program = new ProgramDB(args[0], language, language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("instruction fixture");
            try {
                byte[] bytes = new byte[32];
                for (int i = 0; i < args[2].length() / 2; i++) {
                    bytes[i] = (byte) Integer.parseInt(args[2].substring(i * 2, i * 2 + 2), 16);
                }
                var start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
                program.getMemory().createInitializedBlock("code", start,
                    new java.io.ByteArrayInputStream(bytes), bytes.length, monitor, false).setExecute(true);
                int[] offsets = args[1].startsWith("x86") ? new int[]{0, 3, 4} : new int[]{0, 4, 8};
                for (int offset : offsets) {
                    if (!new DisassembleCommand(start.add(offset), null, false).applyTo(program, monitor)) {
                        throw new IllegalStateException("Could not disassemble fixture at " + offset);
                    }
                }
            } finally { program.endTransaction(tx, true); }
            state.getProject().getProjectData().getRootFolder().createFile(args[0], program, monitor);
        } finally { program.release(this); }
    }
}
