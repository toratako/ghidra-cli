
import ghidra.app.script.GhidraScript;
public class AddDenseSearchBlock extends GhidraScript {
    public void run() throws Exception {
        currentProgram.getMemory().createInitializedBlock("dense",
            currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(0x100000),
            16 * 1024 * 1024, (byte) 0, monitor, false);
    }
}
