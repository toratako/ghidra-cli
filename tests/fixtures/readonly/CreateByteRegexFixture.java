
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;
public class CreateByteRegexFixture extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
        var program = new ProgramDB(getScriptArgs()[0], language,
            language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("byte regex fixture");
            try {
                var memory = program.getMemory();
                var space = program.getAddressFactory().getDefaultAddressSpace();
                String[] hex = {"90488b000aff8090488b11223344c3",
                    "61616161612050617373776f726420544f4b454e20746f6b656e", "1234", "5678", "1234", "5678"};
                long[] starts = {0x1000, 0x2000, 0x5000, 0x6000, 0x7000, 0x7002};
                for (int i = 0; i < hex.length; i++) {
                    byte[] bytes = java.util.HexFormat.of().parseHex(hex[i]);
                    memory.createInitializedBlock("raw" + i, space.getAddress(starts[i]),
                        new java.io.ByteArrayInputStream(bytes), bytes.length, monitor, false);
                }
                memory.createUninitializedBlock("uninitialized", space.getAddress(0x8000), 0x100, false);
                memory.createInitializedBlock("chunk_boundary", space.getAddress(0x10000),
                    0x8000, (byte) 0xee, monitor, false);
                memory.setBytes(space.getAddress(0x13ffe), java.util.HexFormat.of().parseHex("12345678"));
                memory.createInitializedBlock("regex_overlay", space.getAddress(0x1000),
                    new java.io.ByteArrayInputStream(new byte[]{(byte) 0xca, (byte) 0xfe}),
                    2, monitor, true);
            } finally { program.endTransaction(tx, true); }
            state.getProject().getProjectData().getRootFolder()
                .createFile(getScriptArgs()[0], program, monitor);
        } finally { program.release(this); }
    }
}
