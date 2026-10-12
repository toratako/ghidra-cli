import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import java.io.ByteArrayInputStream;

public class CreateSparseStringFixture extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
        var program = new ProgramDB(getScriptArgs()[0], language,
            language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("sparse strings");
            try {
                var space = program.getAddressFactory().getDefaultAddressSpace();
                var memory = program.getMemory();
                var from = space.getAddress(0x1000);
                memory.createInitializedBlock("references", from, 8, (byte) 0, monitor, false);

                var partial = space.getAddress(0x2000);
                memory.createInitializedBlock("partial_start", partial,
                    new ByteArrayInputStream(new byte[]{'B', 'R', 'O', 'K'}), 4, monitor, false);
                memory.createUninitializedBlock("partial_tail", partial.add(4), 4, false);
                program.getListing().createData(partial, StringDataType.dataType, 8);

                var prefix = space.getAddress(0x3000);
                memory.createInitializedBlock("terminated_prefix", prefix,
                    new ByteArrayInputStream(new byte[]{'o', 'k', 0}), 3, monitor, false);
                memory.createUninitializedBlock("unused_string_tail", prefix.add(3), 5, false);
                program.getListing().createData(prefix, new ArrayDataType(CharDataType.dataType, 8, 1));

                var start = space.getAddress(0x10000);
                memory.createInitializedBlock("string", start,
                    new ByteArrayInputStream(new byte[]{'l', 'i', 'v', 'e', 0, 0, 0, 0}),
                    8, monitor, false);
                int tailLength = 0x60000000;
                memory.createUninitializedBlock("huge_tail", start.add(8), tailLength, false);
                var aggregate = new StructureDataType("HugeStringContainer", 0);
                aggregate.add(StringDataType.dataType, 8, "text", null);
                aggregate.add(new ArrayDataType(Undefined1DataType.dataType, tailLength, 1),
                    "uninitialized", null);
                program.getListing().createData(start, aggregate);

                var references = program.getReferenceManager();
                references.addMemoryReference(from, start.add(2), RefType.DATA,
                    SourceType.USER_DEFINED, 0);
                references.addMemoryReference(from.add(1), partial, RefType.DATA,
                    SourceType.USER_DEFINED, 0);
                references.addMemoryReference(from.add(2), prefix.add(1), RefType.DATA,
                    SourceType.USER_DEFINED, 0);
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
