
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSpace;
public class CreateBlockConstraints extends GhidraScript {
    public void run() throws Exception {
        var memory = currentProgram.getMemory();
        memory.createInitializedBlock("byte_backing", toAddr(0x8000), 0x40, (byte) 0x5a, monitor, false);
        // The latter half maps currently absent backing bytes.
        memory.createByteMappedBlock("byte_view", toAddr(0x9000), toAddr(0x8000), 0x80, false);
        memory.createInitializedBlock("bit_backing", toAddr(0xb000), 0x10, (byte) 0x5a, monitor, false);
        memory.createBitMappedBlock("bit_view", toAddr(0xc000), toAddr(0xb000), 0x80, false);
        memory.createBitMappedBlock("unmapped_bit_view", toAddr(0xe000), toAddr(0xd000), 0x80, false);
        memory.createInitializedBlock("constraint_bank", toAddr(0x2000), 0x10, (byte) 0x33, monitor, true);
        memory.createInitializedBlock("other_bank", AddressSpace.OTHER_SPACE.getAddress(0x2000),
            0x10, (byte) 0x22, monitor, true);
    }
}
