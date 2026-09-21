import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;

public class CreateMemoryInfoFixture extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
        var program = new ProgramDB(getScriptArgs()[0], language,
            language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("memory info fixture");
            try {
                var space = program.getAddressFactory().getDefaultAddressSpace();
                var memory = program.getMemory();
                var listing = program.getListing();
                var symbols = program.getSymbolTable();
                var code = memory.createInitializedBlock("code", space.getAddress(0x1000),
                    0x200, (byte) 0, monitor, false);
                code.setRead(true);
                code.setWrite(false);
                code.setExecute(true);
                var data = memory.createInitializedBlock("data", space.getAddress(0x2000),
                    0x100, (byte) 0, monitor, false);
                data.setRead(true);
                data.setWrite(true);
                data.setExecute(false);
                memory.createUninitializedBlock("bss", space.getAddress(0x3000), 0x100, false);

                memory.setBytes(code.getStart(), new byte[]{(byte) 0xb8, 1, 0, 0, 0});
                var instructionRange = new AddressSet(code.getStart(), code.getStart().add(4));
                if (!new DisassembleCommand(code.getStart(), instructionRange, false)
                        .applyTo(program, monitor)) {
                    throw new IllegalStateException("Could not disassemble fixture");
                }
                program.getFunctionManager().createFunction("info_function", code.getStart(),
                    new AddressSet(code.getStart(), space.getAddress(0x1017)), SourceType.USER_DEFINED);
                listing.createData(space.getAddress(0x1010), QWordDataType.dataType);

                var record = new StructureDataType(new CategoryPath("/memory_info"), "InfoRecord", 0);
                record.add(DWordDataType.dataType, "header", null);
                record.add(new ArrayDataType(WordDataType.dataType, 4, 2), "values", null);
                listing.createData(data.getStart(), record);
                symbols.createLabel(data.getStart(), "info_record", SourceType.USER_DEFINED);
                symbols.createLabel(data.getStart(), "1000", SourceType.USER_DEFINED);
                listing.createData(space.getAddress(0x3010), DWordDataType.dataType);

                var overlay = memory.createInitializedBlock("info_overlay", code.getStart(),
                    0x10, (byte) 0, monitor, true);
                listing.createData(overlay.getStart(), DWordDataType.dataType);
                symbols.createLabel(overlay.getStart(), "info_overlay_data", SourceType.USER_DEFINED);
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
