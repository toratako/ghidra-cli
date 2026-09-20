import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.StringUTF8DataType;
import ghidra.program.model.data.UnicodeDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

public class CreateStringFixture extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
        var program = new ProgramDB(getScriptArgs()[0], language,
            language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("string fixture");
            try {
                var space = program.getAddressFactory().getDefaultAddressSpace();
                for (int encoding = 0; encoding < 2; encoding++) {
                    for (int i = 1; i < getScriptArgs().length; i++) {
                        String value = getScriptArgs()[i];
                        // Exercise both terminated and fixed-length unterminated data.
                        String stored = value.equals("plain") ? value : value + "\0";
                        byte[] bytes = stored.getBytes(encoding == 0
                            ? StandardCharsets.UTF_8 : StandardCharsets.UTF_16LE);
                        var address = space.getAddress(0x2000 + encoding * 0x1000 + (i - 1) * 0x100);
                        program.getMemory().createInitializedBlock("string" + encoding + "_" + i,
                            address, new ByteArrayInputStream(bytes), bytes.length, monitor, false);
                        program.getListing().createData(address, encoding == 0
                            ? StringUTF8DataType.dataType : UnicodeDataType.dataType, bytes.length);
                    }
                }
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
