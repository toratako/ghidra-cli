
import ghidra.app.script.GhidraScript;
public class CreateNestedPatchMapping extends GhidraScript {
    public void run() throws Exception {
        var memory = currentProgram.getMemory();
        memory.createByteMappedBlock("nested_patch_view",
            toAddr(0x2000), toAddr(0x3000), 16, false);
        memory.createBitMappedBlock("nested_patch_bits",
            toAddr(0x2100), toAddr(0x3001), 8, false);
        memory.createByteMappedBlock("nested_bit_bytes",
            toAddr(0x2200), toAddr(0x2100), 8, false);
        memory.createBitMappedBlock("nested_bits_of_bits",
            toAddr(0x2300), toAddr(0x2103), 8, false);
        memory.createByteMappedBlock("cyclic_patch_view",
            toAddr(0x5000), toAddr(0x5000), 1, false);
        memory.createByteMappedBlock("shifted_patch_view",
            toAddr(0x5100), toAddr(0x5101), 8, false);
        memory.createInitializedBlock("shifted_patch_source",
            toAddr(0x5108), 1, (byte) 0x5a, monitor, false);
        memory.createByteMappedBlock("large_shifted_patch_view",
            toAddr(0x10000), toAddr(0x10001), 16 * 1024, false);
        memory.createInitializedBlock("large_shifted_patch_source",
            toAddr(0x14000), 1, (byte) 0x5a, monitor, false);
        for (int i = 63; i >= 0; i--) {
            memory.createByteMappedBlock("deep_patch_view_" + i, toAddr(0x6000 + 16 * i),
                toAddr(i == 63 ? 0x3001 : 0x6000 + 16 * (i + 1)), 1, false);
        }
    }
}
