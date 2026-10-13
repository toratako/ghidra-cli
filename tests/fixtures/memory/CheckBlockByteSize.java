
import ghidra.app.script.GhidraScript;
public class CheckBlockByteSize extends GhidraScript {
    public void run() throws Exception {
        var block = currentProgram.getMemory().getBlock(".renamed_odd");
        long start = Long.parseLong(getScriptArgs()[0], 16);
        if (block == null || block.getStart().getOffset() != start
                || block.getEnd().getOffset() != start + 2 || block.getSize() != 3)
            throw new IllegalStateException("Block creation did not preserve byte offsets and size");
    }
}
