import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;

public class CreateCallSignatureFixture extends GhidraScript {
    private Function function(Program program, String name, int offset, String hex) throws Exception {
        var address = program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        program.getMemory().setBytes(address, bytes);
        var body = new AddressSet(address, address.add(bytes.length - 1));
        if (!new DisassembleCommand(address, body, true).applyTo(program, monitor)) {
            throw new IllegalStateException("Cannot disassemble " + name);
        }
        var function = program.getFunctionManager().createFunction(name, address, body, SourceType.USER_DEFINED);
        function.setCallingConvention("__cdecl");
        function.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED);
        function.setSignatureSource(SourceType.USER_DEFINED);
        return function;
    }

    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:32:default"));
        var program = new ProgramDB(getScriptArgs()[0], language,
            language.getCompilerSpecByID(new CompilerSpecID("gcc")), this);
        try {
            int tx = program.startTransaction("call signature fixture");
            try {
                var space = program.getAddressFactory().getDefaultAddressSpace();
                var block = program.getMemory().createInitializedBlock("code", space.getAddress(0x1000),
                    0x1000, (byte) 0xcc, monitor, false);
                block.setExecute(true);
                var callee = function(program, "callee", 0x1100, "8b442404c3");
                callee.addParameter(new ParameterImpl("value", IntegerDataType.dataType, program), SourceType.USER_DEFINED);
                // Two direct calls to the same saved one-argument prototype.
                function(program, "caller", 0x1000, "6811111111e8f600000083c4046822222222e8e900000083c404c3");
                var indirect = function(program, "indirect_caller", 0x1200, "8b442404ffd0c3");
                indirect.addParameter(new ParameterImpl("callback", IntegerDataType.dataType, program), SourceType.USER_DEFINED);
                var thunk = function(program, "caller_thunk", 0x1300, "e9fbfdffff");
                thunk.setThunkedFunction(callee);
                program.getListing().getInstructionAt(space.getAddress(0x1300)).setFlowOverride(FlowOverride.CALL);
                function(program, "branch_caller", 0x1400, "e9fbfcffff");
            } finally {
                program.endTransaction(tx, true);
            }
            state.getProject().getProjectData().getRootFolder().createFile(getScriptArgs()[0], program, monitor);
        } finally {
            program.release(this);
        }
    }
}
