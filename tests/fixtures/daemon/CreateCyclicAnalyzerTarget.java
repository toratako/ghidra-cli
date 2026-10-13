
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
public class CreateCyclicAnalyzerTarget extends GhidraScript {
    public void run() throws Exception {
        var language = currentProgram.getLanguage();
        var program = new ProgramDB(getScriptArgs()[0], language,
            language.getDefaultCompilerSpec(), this);
        try {
            int transaction = program.startTransaction("cyclic analyzer target");
            try {
                var address = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x5000);
                program.getMemory().createByteMappedBlock("cycle", address, address, 1, false);
            } finally { program.endTransaction(transaction, true); }
            state.getProject().getProjectData().getRootFolder()
                .createFile(getScriptArgs()[0], program, monitor);
        } finally { program.release(this); }
    }
}
