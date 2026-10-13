
import ghidra.app.script.GhidraScript;
public class CreateRecursiveReadMappings extends GhidraScript {
    public void run() throws Exception {
        var memory = currentProgram.getMemory();
        memory.createByteMappedBlock("self_shifted", toAddr(0x10000),
            toAddr(0x10001), 16 * 1024, false);
        memory.createInitializedBlock("shifted_source", toAddr(0x14000),
            1, (byte) 0x5a, monitor, false);
        memory.createByteMappedBlock("cycle", toAddr(0x20000), toAddr(0x20000), 1, false);
        memory.createInitializedBlock("before_cycle", toAddr(0x1ffff),
            1, (byte) 0x24, monitor, false);
        memory.createByteMappedBlock("large_self_shifted", toAddr(0x1000000),
            toAddr(0x1000001), 16 * 1024 * 1024, false);
        memory.createInitializedBlock("large_shifted_source", toAddr(0x2000000),
            1, (byte) 0x5a, monitor, false);
        memory.createInitializedBlock("bit_source", toAddr(0x4000000),
            1, (byte) 0x5a, monitor, false);
        memory.createBitMappedBlock("inner_bits", toAddr(0x6000000), toAddr(0x4000000), 8, false);
        memory.createBitMappedBlock("outer_bits", toAddr(0x5000000), toAddr(0x6000003), 8, false);
        for (int i = 0; i < 3; i++) {
            long start = 0x3000000 + i * 0x100000;
            memory.createByteMappedBlock("mixed_deep_" + i, toAddr(start),
                toAddr(start + 1), 65552, false);
            memory.createByteMappedBlock("mixed_tail_" + i, toAddr(start + 65552),
                toAddr(i == 2 ? start : 0x5000000 + i * 7), 1, false);
        }
        memory.createByteMappedBlock("sparse_shift", toAddr(0x7000000), toAddr(0x7000002), 4, false);
        memory.createInitializedBlock("sparse_seed", toAddr(0x7000004), 1, (byte) 0x6b, monitor, false);
        memory.createByteMappedBlock("wide_shift", toAddr(0x7100000), toAddr(0x7100002), 4, false);
        memory.createInitializedBlock("wide_seed", toAddr(0x7100004),
            new java.io.ByteArrayInputStream(new byte[]{0x6c, 0x6d}), 2, monitor, false);
        memory.createInitializedBlock("back_seed", toAddr(0x7200000),
            new java.io.ByteArrayInputStream(new byte[]{0x6e, 0x6f}), 2, monitor, false);
        memory.createByteMappedBlock("back_shift", toAddr(0x7200002), toAddr(0x7200000), 4, false);
    }
}
