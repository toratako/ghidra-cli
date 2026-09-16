import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

public class CreateQueryFixture extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
        var program = new ProgramDB(getScriptArgs()[0], language,
            language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("query fixture");
            try {
                var space = program.getAddressFactory().getDefaultAddressSpace();
                program.getMemory().createInitializedBlock("code", space.getAddress(0x1000),
                    0x1000, (byte) 0, monitor, false);
                String[] names = {"FILE_A", "skip", "FILE_B", "file_C", "ÄPFEL", "İSTANBUL", "ΟΣ", "Σ", "東京"};
                for (int i = 0; i < names.length; i++) {
                    var entry = space.getAddress(0x1000 + 0x10 * i);
                    var function = program.getFunctionManager().createFunction(names[i], entry,
                        new AddressSet(entry, entry.add(i)), SourceType.USER_DEFINED);
                    if (i % 2 == 0) function.addTag("selected");
                    program.getDataTypeManager().addDataType(new StructureDataType(names[i], i + 1), null);
                    // Several comment types at the same address must count as separate rows.
                    for (int type : new int[] {CodeUnit.EOL_COMMENT, CodeUnit.PRE_COMMENT, CodeUnit.POST_COMMENT, CodeUnit.PLATE_COMMENT}) {
                        program.getListing().setComment(entry, type, names[i] + "_" + type);
                    }
                    String text = i == 1 ? "skip" : "FILE_string_" + i;
                    byte[] bytes = (text + "\0").getBytes(StandardCharsets.US_ASCII);
                    var address = space.getAddress(0x3000 + i * 0x100);
                    program.getMemory().createInitializedBlock("string" + i, address,
                        new ByteArrayInputStream(bytes), bytes.length, monitor, false);
                    program.getListing().createData(address, StringDataType.dataType, bytes.length);
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
