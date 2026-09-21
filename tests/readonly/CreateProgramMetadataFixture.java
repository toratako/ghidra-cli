import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.util.DefaultLanguageService;

public class CreateProgramMetadataFixture extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
        var program = new ProgramDB(getScriptArgs()[0], language, language.getDefaultCompilerSpec(), this);
        try {
            int transaction = program.startTransaction("program metadata fixture");
            try {
                var address = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
                program.getMemory().createInitializedBlock("data", address,
                    0x100, (byte) 0x55, monitor, false);
                var relocations = program.getRelocationTable();
                relocations.add(address, Status.APPLIED, 17,
                    new long[] {-1, 9007199254740993L, Long.MIN_VALUE, Long.MAX_VALUE},
                    new byte[] {0, (byte) 0x80, (byte) 0xff}, "relocation_alpha");
                // Multiple relocations at one address retain their order and evidence.
                relocations.add(address, Status.SKIPPED, 3, new long[0], new byte[0], null);
                relocations.add(address.add(0x10), Status.FAILURE, 7, null, (byte[]) null,
                    "relocation_beta");
                var overlay = program.getMemory().createInitializedBlock("relocation_overlay",
                    address, 0x20, (byte) 0, monitor, true);
                relocations.add(overlay.getStart(), Status.UNSUPPORTED, 23,
                    new long[] {8}, (byte[]) null, "relocation_overlay");
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
