import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.Undefined8DataType;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;

public class CreateReturnTypeFixture extends GhidraScript {
    private ProgramDB program;

    private Function function(String name, long offset, byte[] bytes) throws Exception {
        var address = program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
        var body = new AddressSet(address, address.add(bytes.length - 1));
        program.getMemory().setBytes(address, bytes);
        if (!new DisassembleCommand(address, body, false).applyTo(program, monitor))
            throw new IllegalStateException("Failed to disassemble " + name);
        return program.getFunctionManager().createFunction(name, address, body, SourceType.USER_DEFINED);
    }

    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
        program = new ProgramDB(getScriptArgs()[0], language,
            language.getCompilerSpecByID(new CompilerSpecID("gcc")), this);
        try {
            int tx = program.startTransaction("return type fixture");
            try {
                var space = program.getAddressFactory().getDefaultAddressSpace();
                var block = program.getMemory().createInitializedBlock("code", space.getAddress(0x1000),
                    0x100, (byte) 0xcc, monitor, false);
                block.setExecute(true);
                // *buffer += count; both register parameters are inferred, absent from the DB.
                byte[] update = {(byte) 0x8b, 0x07, 0x01, (byte) 0xf0, (byte) 0x89, 0x07, (byte) 0xc3};
                function("inferred", 0x1000, update);
                var target = function("thunk_target", 0x1020, update);
                function("zero", 0x1040, new byte[] {(byte) 0xc3});
                function("inferred_thunk", 0x1060, new byte[] {(byte) 0xc3}).setThunkedFunction(target);
                // addsd xmm0, xmm0; movsd [rdi], xmm0; ret: preserve the floating-point ABI.
                function("floating", 0x1080,
                    new byte[] {(byte) 0xf2, 0x0f, 0x58, (byte) 0xc0,
                        (byte) 0xf2, 0x0f, 0x11, 0x07, (byte) 0xc3});
                var partial = function("partial", 0x10a0, update);
                partial.setCallingConvention(Function.DEFAULT_CALLING_CONVENTION_STRING);
                partial.addParameter(new ParameterImpl("buffer", Undefined8DataType.dataType,
                    program.getRegister("RDI"), program), SourceType.USER_DEFINED);
                partial.getParameter(0).setComment("retain partially saved parameter");
                var unmapped = space.getAddress(0x9000);
                program.getFunctionManager().createFunction("unmapped", unmapped,
                    new AddressSet(unmapped), SourceType.USER_DEFINED);
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
