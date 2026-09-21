import ghidra.app.script.GhidraScript;
import java.io.ByteArrayInputStream;

public class CreateMemorySources extends GhidraScript {
    public void run() throws Exception {
        var memory = currentProgram.getMemory();
        byte[] firstBytes = new byte[32];
        byte[] secondBytes = new byte[16];
        for (int i = 0; i < firstBytes.length; i++) firstBytes[i] = (byte) (0x40 + i);
        for (int i = 0; i < secondBytes.length; i++) secondBytes[i] = (byte) (0x70 + i);
        var first = memory.createFileBytes("archive-member", 0x200, firstBytes.length,
            new ByteArrayInputStream(firstBytes), monitor);
        var second = memory.createFileBytes("second-input", 0x500, secondBytes.length,
            new ByteArrayInputStream(secondBytes), monitor);
        var left = memory.createInitializedBlock("source_left", toAddr(0x2000), first, 3, 4, false);
        var right = memory.createInitializedBlock("source_right", toAddr(0x2004), first, 9, 4, false);
        memory.join(left, right);
        memory.createInitializedBlock("source_next", toAddr(0x2008), second, 1, 4, false);
        memory.createInitializedBlock("original_overlay", toAddr(0x1000), second, 4, 4, true);
        memory.createUninitializedBlock("source_bss", toAddr(0x3000), 4, false);
        memory.createInitializedBlock("source_synthetic", toAddr(0x4000), 4, (byte) 0x7f, monitor, false);
        memory.createByteMappedBlock("source_byte_mapped", toAddr(0x5000), toAddr(0x2000), 4, false);
        memory.createBitMappedBlock("source_bit_mapped", toAddr(0x6000), toAddr(0x2000), 8, false);
    }
}
