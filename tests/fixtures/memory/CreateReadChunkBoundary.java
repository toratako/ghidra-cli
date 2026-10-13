
import ghidra.app.script.GhidraScript;
public class CreateReadChunkBoundary extends GhidraScript {
    public void run() throws Exception {
        currentProgram.getMemory().createInitializedBlock("read_chunk_boundary",
            toAddr(0xa000), 16 * 1024, (byte) 0x42, monitor, false);
    }
}
