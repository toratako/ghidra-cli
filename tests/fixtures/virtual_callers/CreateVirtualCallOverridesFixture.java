import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;

/** Saved native overrides must supersede the instruction's original CALLIND. */
public class CreateVirtualCallOverridesFixture extends GhidraScript {
    private ProgramDB program;

    private Address address(long offset) {
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }

    private Function function(String name, long offset, int... encoded) throws Exception {
        byte[] bytes = new byte[encoded.length];
        for (int i = 0; i < encoded.length; i++) bytes[i] = (byte) encoded[i];
        Address entry = address(offset);
        AddressSet body = new AddressSet(entry, entry.add(bytes.length - 1));
        program.getMemory().setBytes(entry, bytes);
        if (!new DisassembleCommand(entry, body, true).applyTo(program, monitor)) {
            throw new IllegalStateException("Cannot disassemble " + name);
        }
        Function result = program.getFunctionManager().createFunction(name, entry, body,
            SourceType.USER_DEFINED);
        result.setCallingConvention("__cdecl");
        result.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED);
        return result;
    }

    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
        program = new ProgramDB(getScriptArgs()[0], language, language.getDefaultCompilerSpec(), this);
        try {
            int transaction = program.startTransaction("virtual call flow override fixture");
            try {
                program.getMemory().createInitializedBlock("code", address(0x1000), 0x400,
                    (byte) 0, monitor, false).setExecute(true);
                program.getMemory().createInitializedBlock("table", address(0x3000), 0x40,
                    (byte) 0, monitor, false).setWrite(true);
                function("virtual_target", 0x1000, 0xb8, 42, 0, 0, 0, 0xc3);
                function("other_target", 0x1040, 0xb8, 9, 0, 0, 0, 0xc3);
                String[] names = {"ordinary_indirect", "overridden_branch", "overridden_return",
                    "overridden_direct", "overridden_call_return"};
                for (int i = 0; i < names.length; i++) {
                    // mov eax,0x3020; call [rax]; ret
                    long entry = 0x1100 + 0x40L * i;
                    function(names[i], entry, 0xb8, 0x20, 0x30, 0, 0, 0xff, 0x10, 0xc3);
                    var call = program.getListing().getInstructionAt(address(entry + 5));
                    if (i == 1) call.setFlowOverride(FlowOverride.BRANCH);
                    else if (i == 2) call.setFlowOverride(FlowOverride.RETURN);
                    else if (i == 3) {
                        var reference = program.getReferenceManager().addMemoryReference(
                            call.getAddress(), address(0x1040), RefType.CALL_OVERRIDE_UNCONDITIONAL,
                            SourceType.USER_DEFINED, 0);
                        program.getReferenceManager().setPrimary(reference, true);
                    } else if (i == 4) call.setFlowOverride(FlowOverride.CALL_RETURN);
                }
                program.getMemory().setLong(address(0x3020), 0x1000);
                program.getSymbolTable().createLabel(address(0x3020), "virtual_address_point",
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
