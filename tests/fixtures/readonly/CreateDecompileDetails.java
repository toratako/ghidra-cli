
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
public class CreateDecompileDetails extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:64:default"));
        var program = new ProgramDB(getScriptArgs()[0], language, language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("decompile details fixture");
            try {
                var space = program.getAddressFactory().getDefaultAddressSpace();
                var code = program.getMemory().createInitializedBlock("code", space.getAddress(0x1000), 0x100, (byte)0xc3, monitor, false);
                code.setRead(true); code.setWrite(false); code.setExecute(true);
                var data = program.getMemory().createInitializedBlock("data", space.getAddress(0x2000), 0x100, (byte)0xc3, monitor, false);
                data.setRead(true); data.setWrite(true); data.setExecute(false);
                program.getMemory().createInitializedBlock("bad", space.getAddress(0x2100), 1, (byte)0x0f, monitor, false);
                var fm = program.getFunctionManager();
                var source = SourceType.USER_DEFINED;
                int[] entries = {0x1000, 0x1040, 0x1080, 0x2000, 0x2100, 0x9000};
                String[] names = {"clean", "warned", "thunk", "nonexec", "bad", "unmapped"};
                for (int i = 0; i < entries.length; i++) {
                    var address = space.getAddress(entries[i]);
                    var function = fm.createFunction(names[i], address, new AddressSet(address, address), source);
                    if (entries[i] < 0x2100) {
                        if (!new DisassembleCommand(address, new AddressSet(address, address), false).applyTo(program, monitor))
                            throw new IllegalStateException("Failed to disassemble fixture");
                        function.setCallingConvention("__cdecl");
                        function.setReturnType(VoidDataType.dataType, source);
                    }
                }
                // Entry attributes must not describe all disjoint body ranges.
                var clean = fm.getFunctionAt(space.getAddress(0x1000));
                var body = new AddressSet(clean.getBody());
                body.add(space.getAddress(0x2020));
                clean.setBody(body);
                var warned = fm.getFunctionAt(space.getAddress(0x1040));
                warned.setCallingConvention("unknown");
                warned.setReturnType(IntegerDataType.dataType, source);
                warned.setComment("WARNING: user-supplied note\ncontinued line 日本語");
                var external = program.getExternalManager().addExtFunction("library", "outside", null, source).getFunction();
                fm.getFunctionAt(space.getAddress(0x1080)).setThunkedFunction(external);
                // A WARNING in a string literal is not a comment diagnostic.
                var stringAddr = space.getAddress(0x3000);
                var text = "WARNING: string literal".getBytes(java.nio.charset.StandardCharsets.UTF_8);
                program.getMemory().createInitializedBlock("strings", stringAddr, text.length + 1, (byte)0, monitor, false);
                program.getMemory().setBytes(stringAddr, text);
                program.getListing().createData(stringAddr, TerminatedStringDataType.dataType, text.length + 1);
                var literalAddr = space.getAddress(0x1060);
                byte[] bytes = {(byte)0xb8, 0, 0x30, 0, 0, (byte)0xc3};
                program.getMemory().setBytes(literalAddr, bytes);
                new DisassembleCommand(literalAddr, new AddressSet(literalAddr, literalAddr.add(5)), false).applyTo(program, monitor);
                var literal = fm.createFunction("literal", literalAddr, new AddressSet(literalAddr, literalAddr.add(5)), source);
                literal.setCallingConvention("__cdecl");
                literal.setReturnType(new PointerDataType(CharDataType.dataType, program.getDataTypeManager()), source);
            } finally { program.endTransaction(tx, true); }
            state.getProject().getProjectData().getRootFolder().createFile(getScriptArgs()[0], program, monitor);
        } finally { program.release(this); }
    }
}
