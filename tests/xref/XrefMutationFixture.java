import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.OffsetReference;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.ShiftedReference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;

public class XrefMutationFixture extends GhidraScript {
    private Program p;

    private Address a(long offset) {
        return p.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }

    private void check(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }

    public void run() throws Exception {
        if (getScriptArgs()[0].equals("verify-special")) {
            p = currentProgram;
            var refs = p.getReferenceManager();
            var offset = refs.getReference(a(0x1030), a(0x2004), 0);
            check(offset instanceof OffsetReference && ((OffsetReference) offset).getOffset() == 4
                && ((OffsetReference) offset).getBaseAddress().equals(a(0x2000))
                && offset.isPrimary() && offset.getSource() == SourceType.USER_DEFINED,
                "Offset reference changed");
            var shifted = refs.getReference(a(0x1040), a(0x2000), 0);
            check(shifted instanceof ShiftedReference && ((ShiftedReference) shifted).getShift() == 2
                && shifted.isPrimary() && shifted.getSource() == SourceType.USER_DEFINED,
                "Shifted reference changed");
            check(refs.getReferencesFrom(a(0x1020), 0)[0].isExternalReference(),
                "External reference changed");
            check(refs.getReferencesFrom(a(0x1020), 1)[0].isRegisterReference(),
                "Register reference changed");
            var fallthrough = p.getListing().getInstructionAt(a(0x10a0));
            check(fallthrough.isFallThroughOverridden() && fallthrough.getFallThrough().equals(a(0x2000)),
                "Fallthrough override changed");
            check(refs.getReference(a(0x10a0), a(0x2000), -1).isPrimary(),
                "Fallthrough primary changed");
            var override = refs.getReference(a(0x10b0), a(0x2000), -1);
            check(override.getReferenceType() == RefType.CALL_OVERRIDE_UNCONDITIONAL && override.isPrimary(),
                "Call override primary changed");
            boolean overriddenCall = false;
            for (var op : p.getListing().getInstructionAt(a(0x10b0)).getPcode(true)) {
                if (op.getOpcode() == ghidra.program.model.pcode.PcodeOp.CALL
                        && op.getInput(0).getAddress().equals(a(0x2000))) overriddenCall = true;
            }
            check(overriddenCall, "Call p-code override changed");
            return;
        }

        String name = getScriptArgs()[1];
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:32:default"));
        p = new ProgramDB(name, language, language.getDefaultCompilerSpec(), this);
        try {
            int transaction = p.startTransaction("xref mutation fixture");
            try {
                p.getMemory().createInitializedBlock("code", a(0x1000), 0x200,
                    (byte) 0, monitor, false);
                p.getMemory().createInitializedBlock("target", a(0x2000), 0x40,
                    (byte) 0, monitor, false);
                p.getMemory().createInitializedBlock("overlay", a(0x3000), 0x20,
                    (byte) 0, monitor, true);
                var refs = p.getReferenceManager();
                for (long site = 0x1000; site <= 0x10b0; site += 0x10) {
                    byte[] bytes = site == 0x1080 ? new byte[] {(byte) 0x90}
                        : site == 0x10b0 ? new byte[] {(byte) 0xff, (byte) 0xd0}
                        : new byte[] {(byte) 0xc8, 8, 0, 8};
                    p.getMemory().setBytes(a(site), bytes);
                    check(new DisassembleCommand(a(site),
                        new AddressSet(a(site), a(site + bytes.length - 1)), false)
                        .applyTo(p, monitor), "Could not disassemble fixture instruction");
                    refs.removeAllReferencesFrom(a(site));
                }
                p.getListing().createData(a(0x1100), DWordDataType.dataType);
                p.getSymbolTable().createLabel(a(0x1000), "xref_site", SourceType.USER_DEFINED);
                refs.addMemoryReference(a(0x1010), a(0x2000), RefType.READ, SourceType.ANALYSIS, 0);
                refs.addMemoryReference(a(0x1010), a(0x2010), RefType.READ, SourceType.USER_DEFINED, 0);
                refs.addMemoryReference(a(0x1010), a(0x2000), RefType.DATA, SourceType.USER_DEFINED, 1);
                refs.addExternalReference(a(0x1020), "fixture_library", "external_target", null,
                    SourceType.IMPORTED, 0, RefType.DATA);
                refs.addRegisterReference(a(0x1020), 1, p.getRegister("EAX"), RefType.READ,
                    SourceType.ANALYSIS);
                refs.addOffsetMemReference(a(0x1030), a(0x2000), true, 4,
                    RefType.DATA, SourceType.USER_DEFINED, 0);
                refs.addMemoryReference(a(0x1030), a(0x2010), RefType.DATA, SourceType.USER_DEFINED, 0);
                refs.addShiftedMemReference(a(0x1040), a(0x2000), 2,
                    RefType.DATA, SourceType.USER_DEFINED, 0);
                refs.addMemoryReference(a(0x1040), a(0x2010), RefType.DATA, SourceType.USER_DEFINED, 0);
                p.getListing().getInstructionAt(a(0x10a0)).setFallThrough(a(0x2000));
                refs.addMemoryReference(a(0x10a0), a(0x2010), RefType.DATA, SourceType.USER_DEFINED, -1);
                refs.addMemoryReference(a(0x10b0), a(0x2000), RefType.CALL_OVERRIDE_UNCONDITIONAL,
                    SourceType.USER_DEFINED, -1);
                refs.addMemoryReference(a(0x10b0), a(0x2010), RefType.DATA, SourceType.USER_DEFINED, -1);
                SourceType[] sources = {SourceType.ANALYSIS, SourceType.IMPORTED, SourceType.DEFAULT};
                for (int i = 0; i < sources.length; i++) {
                    refs.addMemoryReference(a(0x1050 + 0x10 * i), a(0x2000), RefType.DATA, sources[i], 0);
                }
            } finally {
                p.endTransaction(transaction, true);
            }
            state.getProject().getProjectData().getRootFolder().createFile(name, p, monitor);
        } finally {
            p.release(this);
        }
    }
}
