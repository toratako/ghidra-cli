import ghidra.app.script.GhidraScript;

public class CreateBinaryExportTail extends GhidraScript {
  public void run() throws Exception {
    byte[] tail = new byte[65543];
    for (int i = 0; i < tail.length; i++) tail[i] = (byte) (i * 17);
    currentProgram
        .getMemory()
        .createInitializedBlock(
            "stream_tail",
            toAddr(0xfffefff9L),
            new java.io.ByteArrayInputStream(tail),
            tail.length,
            monitor,
            false);
    currentProgram
        .getMemory()
        .createByteMappedBlock("initialized_alias", toAddr(0x3000), toAddr(0x1010), 4, false);
    currentProgram
        .getMemory()
        .createByteMappedBlock("nested_alias", toAddr(0x2800), toAddr(0x3000), 4, false);
    currentProgram
        .getMemory()
        .createBitMappedBlock("nested_bits", toAddr(0x2810), toAddr(0x3000), 8, false);
    currentProgram
        .getMemory()
        .createByteMappedBlock(
            "nested_skipped_bytes",
            toAddr(0x2820),
            toAddr(0x3000),
            2,
            new ghidra.program.database.mem.ByteMappingScheme(1, 2),
            false);
    currentProgram
        .getMemory()
        .createByteMappedBlock("nested_partial", toAddr(0x2830), toAddr(0x3000), 8, false);
    byte[] overlay = {0x11, 0x22, 0x33};
    currentProgram
        .getMemory()
        .createInitializedBlock(
            "export_overlay",
            toAddr(0x4000),
            new java.io.ByteArrayInputStream(overlay),
            overlay.length,
            monitor,
            true);
  }
}
