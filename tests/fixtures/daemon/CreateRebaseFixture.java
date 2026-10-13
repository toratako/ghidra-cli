
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;

public class CreateRebaseFixture extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID(getScriptArgs()[1]));
        var program = new ProgramDB(getScriptArgs()[0], language,
            language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("rebase fixture");
            try {
                var space = program.getAddressFactory().getDefaultAddressSpace();
                var memory = program.getMemory();
                var listing = program.getListing();
                // The first block is deliberately below the image base.
                var base = space instanceof ghidra.program.model.address.SegmentedAddressSpace segmented
                    ? segmented.getAddress(0x100, 0) : space.getAddress(0x1000);
                program.setImageBase(base, true);
                memory.createInitializedBlock("low", space.getAddress(0x800),
                    0x10, (byte) 0x17, monitor, false);
                var code = memory.createInitializedBlock("code", space.getAddress(0x2000),
                    0x100, (byte) 0, monitor, false);
                code.setExecute(true);
                memory.createInitializedBlock("data", space.getAddress(0x3000),
                    0x100, (byte) 0x55, monitor, false);
                var mmio = memory.createUninitializedBlock("mmio", space.getAddress(0x5000),
                    0x10, false);
                mmio.setVolatile(true);
                var overlay = memory.createInitializedBlock("rebase_overlay", space.getAddress(0x2000),
                    0x20, (byte) 0x7a, monitor, true);
                listing.setComment(overlay.getStart(), CodeUnit.EOL_COMMENT, "overlay stays");
                if (getScriptArgs()[1].startsWith("avr8")) {
                    memory.createInitializedBlock("other", program.getAddressFactory()
                        .getAddressSpace("mem").getAddress(0x2000), 0x20, (byte) 0x3b, monitor, false);
                }
                if (space instanceof ghidra.program.model.address.SegmentedAddressSpace) {
                    memory.createUninitializedBlock("upper", space.getAddress(0x100000), 0x10, false);
                }
                if (getScriptArgs()[1].equals("x86:LE:64:default")) {
                    memory.setBytes(code.getStart(), new byte[]{(byte) 0xb8, 0x11, 0x22, 0x33, 0x44, (byte) 0xc3});
                    if (!new DisassembleCommand(code.getStart(),
                            new AddressSet(code.getStart(), code.getStart().add(5)), false).applyTo(program, monitor)) {
                        throw new IllegalStateException("Could not disassemble fixture");
                    }
                    program.getFunctionManager().createFunction("rebase_function", code.getStart(),
                        new AddressSet(code.getStart(), code.getStart().add(5)), SourceType.USER_DEFINED);
                    listing.setComment(code.getStart(), CodeUnit.EOL_COMMENT, "manual rebase comment");
                    var pointer = space.getAddress(0x3000);
                    memory.setBytes(pointer, new byte[]{0, 0x20, 0, 0, 0, 0, 0, 0});
                    listing.createData(pointer, new PointerDataType());
                    program.getReferenceManager().addMemoryReference(pointer.add(0x10), code.getStart(),
                        RefType.DATA, SourceType.USER_DEFINED, 0);
                    program.getRelocationTable().add(pointer, Status.APPLIED, 17,
                        new long[]{0x2000}, new byte[]{1, 2, 3, 4}, "fixed_pointer");
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
