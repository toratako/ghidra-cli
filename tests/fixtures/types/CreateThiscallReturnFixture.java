import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;

public class CreateThiscallReturnFixture extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:32:default"));
        var program = new ProgramDB(getScriptArgs()[0], language,
            language.getCompilerSpecByID(new CompilerSpecID("windows")), this);
        try {
            int tx = program.startTransaction("thiscall return fixture");
            try {
                var entry = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
                // *ECX += stack[4]; ret 4. Only the ABI-generated 'this' is saved.
                byte[] bytes = {(byte) 0x8b, 0x01, 0x03, 0x44, 0x24, 0x04,
                    (byte) 0x89, 0x01, (byte) 0xc2, 0x04, 0x00};
                var block = program.getMemory().createInitializedBlock("code", entry,
                    bytes.length, (byte) 0xcc, monitor, false);
                block.setExecute(true);
                program.getMemory().setBytes(entry, bytes);
                var body = new AddressSet(entry, entry.add(bytes.length - 1));
                if (!new DisassembleCommand(entry, body, false).applyTo(program, monitor))
                    throw new IllegalStateException("Failed to disassemble method");
                var function = program.getFunctionManager().createFunction("method", entry, body,
                    SourceType.USER_DEFINED);
                function.setCallingConvention("__thiscall");
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
