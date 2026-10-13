
import ghidra.app.script.GhidraScript;
public class ReleaseDeletionTarget extends GhidraScript {
    public void run() {
        if (!currentProgram.getConsumerList().contains(currentProgram))
            throw new IllegalStateException("Deletion released another consumer");
        currentProgram.release(currentProgram);
    }
}
