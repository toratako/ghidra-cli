
import ghidra.app.script.GhidraScript;
public class CheckReopenedCancelledOverlay extends GhidraScript {
    public void run() throws Exception {
        if (currentProgram.getAddressFactory().getAddressSpace("late_bank") != null
                || currentProgram.getMemory().getBlocks().length != 1)
            throw new IllegalStateException("Cancelled overlay/block reappeared after reopen");
    }
}
