import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

public class CreateNestedStringFixture extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
        var program = new ProgramDB(getScriptArgs()[0], language,
            language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("nested string fixture");
            try {
                var space = program.getAddressFactory().getDefaultAddressSpace();
                var start = space.getAddress(0x2000);
                byte[] bytes = "nest_A\0\0nest_B\0\0nest_C\0\0".getBytes(StandardCharsets.US_ASCII);
                program.getMemory().createInitializedBlock("strings", start,
                    new ByteArrayInputStream(bytes), bytes.length, monitor, false);
                var element = new StructureDataType("Element", 0);
                element.add(new ArrayDataType(CharDataType.dataType, 8, 1), "value", null);
                var container = new StructureDataType("Container", 0);
                container.add(StringDataType.dataType, 8, "first", null);
                container.add(new ArrayDataType(element, 2, element.getLength()), "elements", null);
                program.getListing().createData(start, container);
                var from = space.getAddress(0x1000);
                program.getMemory().createInitializedBlock("references", from,
                    3, (byte) 0, monitor, false);
                for (int i = 0; i < 3; i++) {
                    program.getReferenceManager().addMemoryReference(from.add(i), start.add(i * 8 + 2),
                        RefType.DATA, SourceType.USER_DEFINED, 0);
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
