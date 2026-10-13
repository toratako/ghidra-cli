
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
public class CreateFunctionDisasmFixture extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
        var program = new ProgramDB(getScriptArgs()[0], language,
            language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("function disassembly fixture");
            try {
                byte[] bytes = new byte[0x100];
                java.util.Arrays.fill(bytes, (byte) 0x90);
                bytes[0] = 0x48; bytes[1] = (byte) 0x89; bytes[2] = (byte) 0xe5;
                for (int offset : new int[]{3, 6, 0x34, 0x51, 0x66, 0x81, 0xa1, 0xc1, 0xc5}) {
                    bytes[offset] = (byte) 0xc3;
                }
                // Jump across another function to a disjoint tail.
                bytes[0x60] = (byte) 0xe9; bytes[0x61] = 0x1b;
                bytes[0x62] = 0; bytes[0x63] = 0; bytes[0x64] = 0;
                var start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
                program.getMemory().createInitializedBlock("code", start,
                    new java.io.ByteArrayInputStream(bytes), bytes.length, monitor, false).setExecute(true);
                var offsets = new java.util.ArrayList<Integer>();
                for (int offset : new int[]{0, 3, 4, 5, 6, 0x50, 0x51, 0x60, 0x65, 0x66, 0x80, 0x81, 0xa0, 0xc0, 0xc4}) {
                    offsets.add(offset);
                }
                for (int offset = 0x20; offset <= 0x34; offset++) offsets.add(offset);
                for (int offset : offsets) {
                    if (!new DisassembleCommand(start.add(offset), null, false).applyTo(program, monitor)) {
                        throw new IllegalStateException("Could not disassemble fixture at " + offset);
                    }
                }
                var fm = program.getFunctionManager();
                fm.createFunction("short_case", start, new AddressSet(start, start.add(3)), SourceType.USER_DEFINED);
                fm.createFunction("neighbor_case", start.add(4), new AddressSet(start.add(4), start.add(6)), SourceType.USER_DEFINED);
                fm.createFunction("long_case", start.add(0x20), new AddressSet(start.add(0x20), start.add(0x34)), SourceType.USER_DEFINED);
                var splitBody = new AddressSet(start.add(0x50), start.add(0x51));
                splitBody.add(start.add(0x60), start.add(0x64));
                splitBody.add(start.add(0x80), start.add(0x81));
                fm.createFunction("split_case", start.add(0x60), splitBody, SourceType.USER_DEFINED);
                fm.createFunction("gap_case", start.add(0x65), new AddressSet(start.add(0x65), start.add(0x66)), SourceType.USER_DEFINED);
                fm.createFunction("empty_case", start.add(0xb0), new AddressSet(start.add(0xb0)), SourceType.USER_DEFINED);
                fm.createFunction("undefined_gap_case", start.add(0xc0), new AddressSet(start.add(0xc0), start.add(0xc5)), SourceType.USER_DEFINED);
                if (program.getListing().getInstructionContaining(start.add(0xc2)) != null) {
                    throw new IllegalStateException("Fixture gap must remain undefined");
                }
                for (int i = 0; i < 2; i++) {
                    var namespace = program.getSymbolTable().createNameSpace(null,
                        "scope" + i, SourceType.USER_DEFINED);
                    var entry = start.add(0xd0 + i * 0x10);
                    fm.createFunction("shared_target", namespace, entry,
                        new AddressSet(entry), SourceType.USER_DEFINED);
                }
            } finally { program.endTransaction(tx, true); }
            state.getProject().getProjectData().getRootFolder().createFile(getScriptArgs()[0], program, monitor);
        } finally { program.release(this); }
    }
}
