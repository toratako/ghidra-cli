import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;

/** A four-byte pointer ABI independently checks slot stride and LOAD width. */
public class CreateVirtualCallers32Fixture extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:32:default"));
        var program = new ProgramDB(getScriptArgs()[0], language, language.getDefaultCompilerSpec(), this);
        try {
            int transaction = program.startTransaction("32-bit virtual callers fixture");
            try {
                var space = program.getAddressFactory().getDefaultAddressSpace();
                var memory = program.getMemory();
                memory.createInitializedBlock("code", space.getAddress(0x1000), 0x200,
                    (byte) 0, monitor, false).setExecute(true);
                memory.createInitializedBlock("tables", space.getAddress(0x3000), 0x40,
                    (byte) 0, monitor, false).setWrite(true);
                long[] entries = {0x1000, 0x1100, 0x1140};
                String[] names = {"virtual_target", "known_zero", "known_nonzero"};
                byte[][] code = {
                    {(byte)0xb8, 42, 0, 0, 0, (byte)0xc3},
                    {(byte)0xb8, 0x20, 0x30, 0, 0, (byte)0xff, 0x10, (byte)0xc3},
                    {(byte)0xb8, 0x20, 0x30, 0, 0, (byte)0xff, 0x50, 4, (byte)0xc3}
                };
                for (int i = 0; i < entries.length; i++) {
                    var start = space.getAddress(entries[i]);
                    var body = new AddressSet(start, start.add(code[i].length - 1));
                    memory.setBytes(start, code[i]);
                    if (!new DisassembleCommand(start, body, true).applyTo(program, monitor)) {
                        throw new IllegalStateException("Cannot disassemble " + names[i]);
                    }
                    var function = program.getFunctionManager().createFunction(names[i], start, body,
                        SourceType.USER_DEFINED);
                    function.setCallingConvention("__cdecl");
                    function.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED);
                }
                memory.setInt(space.getAddress(0x3020), 0x1000);
                memory.setInt(space.getAddress(0x3024), 0x1000);
                program.getSymbolTable().createLabel(space.getAddress(0x3020), "virtual_address_point",
                    SourceType.USER_DEFINED);
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
