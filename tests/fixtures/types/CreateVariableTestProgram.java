import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
public class CreateVariableTestProgram extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:32:default"));
        var program = new ProgramDB(getScriptArgs()[0], language,
            language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("variable fixture");
            try {
                var address = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
                program.getMemory().createInitializedBlock("code", address, 0x400, (byte) 0, monitor, false);
                String hex = "5589e583ec108b45088945fc8d45fc50e8eb00000083c4048b45fcc9c3";
                byte[] code = new byte[hex.length() / 2];
                for (int i = 0; i < code.length; i++) code[i] = (byte) Integer.parseInt(hex.substring(i*2, i*2+2), 16);
                program.getMemory().setBytes(address, code);
                var sinkAddress = address.add(0x100);
                program.getMemory().setByte(sinkAddress, (byte) 0xc3);
                var function = program.getFunctionManager().createFunction("edit_target", address,
                    new AddressSet(address, address.add(code.length - 1)), SourceType.USER_DEFINED);
                function.setCallingConvention("__cdecl");
                function.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED);
                function.addParameter(new ParameterImpl("input", IntegerDataType.dataType, program), SourceType.USER_DEFINED);
                var sink = program.getFunctionManager().createFunction("sink", sinkAddress,
                    new AddressSet(sinkAddress, sinkAddress), SourceType.USER_DEFINED);
                sink.setCallingConvention("__cdecl");
                sink.addParameter(new ParameterImpl("ptr", new PointerDataType(IntegerDataType.dataType), program), SourceType.USER_DEFINED);
                var methodAddress = address.add(0x200);
                program.getMemory().setBytes(methodAddress, new byte[] {(byte) 0x8b, 0x01, (byte) 0xc3});
                var method = program.getFunctionManager().createFunction("method", methodAddress,
                    new AddressSet(methodAddress, methodAddress.add(2)), SourceType.USER_DEFINED);
                method.updateFunction("__thiscall", new ReturnParameterImpl(IntegerDataType.dataType, program),
                    FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, false, SourceType.USER_DEFINED);
                if (!new DisassembleCommand(methodAddress, null, true).applyTo(program, monitor))
                    throw new IllegalStateException("Method disassembly failed");
                var inferredAddress = address.add(0x300);
                program.getMemory().setBytes(inferredAddress,
                    new byte[] {(byte) 0x8b, 0x44, 0x24, 0x04, (byte) 0x83, (byte) 0xc0, 0x01, (byte) 0xc3});
                program.getFunctionManager().createFunction("inferred", inferredAddress,
                    new AddressSet(inferredAddress, inferredAddress.add(7)), SourceType.USER_DEFINED);
                if (!new DisassembleCommand(inferredAddress, null, true).applyTo(program, monitor))
                    throw new IllegalStateException("Inferred function disassembly failed");
                program.getEquateTable().createEquate("INCREMENT", 1).addReference(inferredAddress.add(4), 1);
                program.getSymbolTable().createLabel(address.add(1), "collision", function, SourceType.USER_DEFINED);
                if (!new DisassembleCommand(address, null, true).applyTo(program, monitor))
                    throw new IllegalStateException("Fixture disassembly failed");
            } finally { program.endTransaction(tx, true); }
            state.getProject().getProjectData().getRootFolder().createFile(getScriptArgs()[0], program, monitor);
        } finally { program.release(this); }
    }
}
