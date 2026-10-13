
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
public class CreateStringRefsFixture extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:64:default"));
        var program = new ProgramDB(args[0], language, language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("string refs fixture");
            try {
                var space = program.getAddressFactory().getDefaultAddressSpace();
                var from = space.getAddress(0x1000);
                program.getMemory().createInitializedBlock("references", from, 0x10, (byte) 0, monitor, false);
                for (int i = 1; i < args.length; i++) {
                    var address = space.getAddress(0x2000 + i * 0x100);
                    byte[] bytes = (args[i] + "\0").getBytes(java.nio.charset.StandardCharsets.UTF_8);
                    program.getMemory().createInitializedBlock("string" + i, address,
                        new java.io.ByteArrayInputStream(bytes), bytes.length, monitor, false);
                    program.getListing().createData(address, StringDataType.dataType, bytes.length);
                    program.getReferenceManager().addMemoryReference(from.add(i), address,
                        RefType.DATA, SourceType.USER_DEFINED, 0);
                }
            } finally { program.endTransaction(tx, true); }
            state.getProject().getProjectData().getRootFolder().createFile(args[0], program, monitor);
        } finally { program.release(this); }
    }
}
