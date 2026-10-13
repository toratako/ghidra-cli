import ghidra.app.script.GhidraScript;
import java.io.ByteArrayInputStream;

public class CreateFileMappings extends GhidraScript {
    public void run() throws Exception {
        var memory = currentProgram.getMemory();
        var original = memory.getBlock(toAddr(0x2000)).getSourceInfos().get(0)
            .getFileBytes().orElseThrow();
        byte[] duplicateBytes = new byte[32];
        java.util.Arrays.fill(duplicateBytes, (byte) 0x90);
        // All public name/span attributes match; this is still a different database source.
        var duplicate = memory.createFileBytes(original.getFilename(), original.getFileOffset(),
            duplicateBytes.length, new ByteArrayInputStream(duplicateBytes), monitor);
        memory.createInitializedBlock("duplicate_source", toAddr(0x7000), duplicate, 3, 4, false);
        memory.createInitializedBlock("same_source", toAddr(0x7100), original, 3, 4, false);
        memory.createInitializedBlock("same_source_overlay", toAddr(0x2000), original, 3, 4, true);
        currentProgram.getSymbolTable().createLabel(toAddr(0x2001), "source_label",
            ghidra.program.model.symbol.SourceType.USER_DEFINED);
        // Saved but never mapped source bytes must not manufacture a reverse result.
        memory.createFileBytes("unloaded", 0x800, duplicateBytes.length,
            new ByteArrayInputStream(duplicateBytes), monitor);
    }
}
