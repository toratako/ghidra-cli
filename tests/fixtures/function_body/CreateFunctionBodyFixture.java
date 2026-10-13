import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;

public class CreateFunctionBodyFixture extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID(getScriptArgs()[1]));
        var program = new ProgramDB(getScriptArgs()[0], language,
            language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("function body fixture");
            try {
                var space = program.getAddressFactory().getDefaultAddressSpace();
                Address base = space instanceof SegmentedAddressSpace segmented
                    ? segmented.getAddress(0x100, 0) : space.getAddress(0x1000);
                program.getMemory().createInitializedBlock("code", base,
                    0x200, (byte) 0x90, monitor, false);
                var functions = program.getFunctionManager();
                var subject = functions.createFunction("subject", base,
                    new AddressSet(base, base.add(0x1f)), SourceType.USER_DEFINED);
                var other = functions.createFunction("other", base.add(0x100),
                    new AddressSet(base.add(0x100), base.add(0x105)), SourceType.USER_DEFINED);
                var thunk = functions.createFunction("body_thunk", base.add(0x140),
                    new AddressSet(base.add(0x140), base.add(0x14f)), SourceType.USER_DEFINED);
                thunk.setThunkedFunction(other);
                program.getExternalManager().addExtFunction("library", "external_body", null,
                    SourceType.USER_DEFINED);
                var overlay = program.getMemory().createInitializedBlock("body_overlay", base,
                    0x80, (byte) 0x90, monitor, true);
                functions.createFunction("overlay_subject", overlay.getStart(),
                    new AddressSet(overlay.getStart(), overlay.getStart().add(0x1f)),
                    SourceType.USER_DEFINED);

                if (!(space instanceof SegmentedAddressSpace)) {
                    program.getMemory().setBytes(base,
                        new byte[] {(byte) 0xb8, 1, 0, 0, 0, (byte) 0xc3});
                    program.getMemory().setBytes(base.add(0x10),
                        new byte[] {(byte) 0xe8, (byte) 0xeb, 0, 0, 0, (byte) 0xc3});
                    for (int offset : new int[] {0, 0x10}) {
                        var command = new DisassembleCommand(base.add(offset), null, true);
                        if (!command.applyTo(program, monitor)) {
                            throw new IllegalStateException(command.getStatusMsg());
                        }
                    }
                    var symbols = program.getSymbolTable();
                    symbols.createLabel(base.add(5), "kept_label", subject, SourceType.USER_DEFINED);
                    symbols.createLabel(base.add(0x15), "removed_label", subject, SourceType.USER_DEFINED);
                    symbols.createLabel(base.add(0x15), "global_label", SourceType.USER_DEFINED);
                    var child = symbols.createNameSpace(subject, "child", SourceType.USER_DEFINED);
                    symbols.createLabel(base.add(0x15), "child_label", child, SourceType.USER_DEFINED);

                    var references = program.getReferenceManager();
                    references.addStackReference(base.add(0x15), 0, -4, RefType.READ, SourceType.USER_DEFINED);
                    references.addRegisterReference(base.add(0x15), 1,
                        program.getRegister("EAX"), RefType.READ, SourceType.USER_DEFINED);
                    var variable = subject.addLocalVariable(new LocalVariableImpl("memory_local", 0,
                        IntegerDataType.dataType, base.add(0x80), program), SourceType.USER_DEFINED);
                    Reference reference = references.addMemoryReference(base.add(0x15), base.add(0x80),
                        RefType.READ, SourceType.USER_DEFINED, 2);
                    // Imported databases can retain variable associations that current public
                    // setAssociation no longer creates. Seed that native state to exercise
                    // setBody's supported disassociation path without a production test hook.
                    var setSymbol = references.getClass().getDeclaredMethod("setSymbolID", Reference.class, long.class);
                    setSymbol.setAccessible(true);
                    setSymbol.invoke(references, reference, variable.getSymbol().getID());
                    var signature = new FunctionDefinitionDataType("local_override");
                    signature.setReturnType(IntegerDataType.dataType);
                    HighFunctionDBUtil.writeOverride(subject, base.add(0x10), signature);
                }
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
