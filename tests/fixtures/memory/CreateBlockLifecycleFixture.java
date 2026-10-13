
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import java.io.ByteArrayInputStream;

public class CreateBlockLifecycleFixture extends GhidraScript {
    public void run() throws Exception {
        var language = DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
        var program = new ProgramDB(getScriptArgs()[0], language,
            language.getDefaultCompilerSpec(), this);
        try {
            int tx = program.startTransaction("block lifecycle fixture");
            try {
                var space = program.getAddressFactory().getDefaultAddressSpace();
                var code = space.getAddress(0x2000);
                var outside = space.getAddress(0x4000);
                program.setImageBase(space.getAddress(0x1000), true);
                var memory = program.getMemory();
                byte[] original = new byte[0x110];
                java.util.Arrays.fill(original, (byte) 0x55);
                System.arraycopy(new byte[]{(byte) 0xb8, 0x11, 0x22, 0x33, 0x44, (byte) 0xc3},
                    0, original, 8, 6);
                var file = memory.createFileBytes("block-original", 0x200, original.length,
                    new ByteArrayInputStream(original), monitor);
                var block = memory.createInitializedBlock("movable", code, file, 8, 0x100, false);
                block.setExecute(true);
                memory.setByte(code.add(0x50), (byte) 0x7f);
                memory.createInitializedBlock("outside", outside, 0x100, (byte) 0x90, monitor, false);
                if (!new DisassembleCommand(code, new AddressSet(code, code.add(5)), false)
                        .applyTo(program, monitor)) throw new IllegalStateException("Fixture disassembly failed");
                var insideBody = new AddressSet(code, code.add(5));
                insideBody.add(outside.add(0x20), outside.add(0x25));
                program.getFunctionManager().createFunction("inside_entry", code, insideBody,
                    SourceType.USER_DEFINED);
                var outsideBody = new AddressSet(outside, outside.add(5));
                outsideBody.add(code.add(0x20), code.add(0x25));
                program.getFunctionManager().createFunction("outside_entry", outside, outsideBody,
                    SourceType.USER_DEFINED);
                program.getSymbolTable().createLabel(code.add(0x30), "moving_label", SourceType.USER_DEFINED);
                program.getSymbolTable().createLabel(outside.add(0x30), "outside_label", SourceType.USER_DEFINED);
                var listing = program.getListing();
                listing.setComment(code, CodeUnit.EOL_COMMENT, "moving comment");
                listing.setComment(outside, CodeUnit.EOL_COMMENT, "outside comment");
                memory.setLong(outside.add(0x40), 0x2000);
                listing.createData(outside.add(0x40), new PointerDataType());
                program.getReferenceManager().addMemoryReference(outside.add(0x50), code,
                    RefType.DATA, SourceType.USER_DEFINED, 0);
                program.getReferenceManager().addMemoryReference(outside.add(0x58), space.getAddress(0x6000),
                    RefType.DATA, SourceType.USER_DEFINED, 0);
                program.getReferenceManager().addMemoryReference(code.add(0x60), outside.add(0x30),
                    RefType.DATA, SourceType.USER_DEFINED, 0);
            } finally { program.endTransaction(tx, true); }
            state.getProject().getProjectData().getRootFolder()
                .createFile(getScriptArgs()[0], program, monitor);
        } finally { program.release(this); }
    }
}
