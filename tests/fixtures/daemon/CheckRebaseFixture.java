
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.address.Address;
import ghidra.program.util.GhidraProgramUtilities;
import java.util.Arrays;

public class CheckRebaseFixture extends GhidraScript {
    private void require(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }
    public void run() throws Exception {
        long base = Long.parseUnsignedLong(getScriptArgs()[0], 16);
        long delta = base - 0x1000;
        var p = currentProgram;
        var space = p.getAddressFactory().getDefaultAddressSpace();
        var memory = p.getMemory();
        var listing = p.getListing();
        require(p.getImageBase().getOffset() == base, "Image base differs");
        require(!p.isChanged(), "Successful rebase was not saved");
        require(!GhidraProgramUtilities.isAnalyzed(p), "Rebase ran analysis");
        for (var entry : new Object[][] {{"low", 0x800L}, {"code", 0x2000L},
                {"data", 0x3000L}, {"mmio", 0x5000L}}) {
            var block = memory.getBlock((String) entry[0]);
            require(block.getStart().getOffset() == (long) entry[1] + delta,
                "Block did not preserve its image-base offset: " + entry[0]);
        }
        require(memory.getBlock("mmio").isVolatile(), "MMIO flags changed");
        var overlay = memory.getBlock("rebase_overlay").getStart();
        require(overlay.getOffset() == 0x2000 && memory.getByte(overlay) == (byte) 0x7a,
            "Overlay bytes or address changed");
        require("overlay stays".equals(listing.getComment(CodeUnit.EOL_COMMENT, overlay)),
            "Overlay metadata changed");
        var other = memory.getBlock("other");
        if (other != null) {
            require(other.getStart().getOffset() == 0x2000 && memory.getByte(other.getStart()) == (byte) 0x3b,
                "Other address space moved");
        }
        var upper = memory.getBlock("upper");
        if (upper != null) require(upper.getStart().getOffset() == 0x100000 + delta,
            "Upper segmented memory did not move");
        if (p.getLanguageID().toString().equals("x86:LE:64:default")) {
            var code = space.getAddress(0x2000 + delta);
            var data = space.getAddress(0x3000 + delta);
            byte[] bytes = new byte[6];
            memory.getBytes(code, bytes);
            require(Arrays.equals(bytes, new byte[]{(byte) 0xb8, 0x11, 0x22, 0x33, 0x44, (byte) 0xc3}),
                "Instruction bytes changed");
            require(listing.getInstructionAt(code) != null && listing.getInstructionAt(code.add(0x20)) == null,
                "Instruction definitions changed");
            var function = p.getFunctionManager().getFunctionAt(code);
            require(function != null && function.getName().equals("rebase_function")
                && function.getBody().contains(code.add(5)), "Function metadata did not move");
            require("manual rebase comment".equals(listing.getComment(CodeUnit.EOL_COMMENT, code)),
                "Comment did not move");
            bytes = new byte[8];
            memory.getBytes(data, bytes);
            require(Arrays.equals(bytes, new byte[]{0, 0x20, 0, 0, 0, 0, 0, 0}), "Pointer bytes were fixed up");
            var pointer = listing.getDataAt(data);
            require(pointer != null && pointer.getValue() instanceof Address
                && ((Address) pointer.getValue()).getOffset() == 0x2000, "Applied pointer changed");
            var refs = p.getReferenceManager().getReferencesFrom(data.add(0x10));
            require(refs.length == 1 && refs[0].getToAddress().equals(code)
                && refs[0].getSource() == ghidra.program.model.symbol.SourceType.USER_DEFINED,
                "User xref did not move");
            var relocations = p.getRelocationTable().getRelocations();
            require(relocations.hasNext(), "Relocation disappeared");
            var relocation = relocations.next();
            require(relocation.getAddress().equals(data)
                && relocation.getStatus() == ghidra.program.model.reloc.Relocation.Status.APPLIED
                && Arrays.equals(relocation.getBytes(), new byte[]{1, 2, 3, 4}),
                "Relocation evidence changed");
        }
    }
}
