import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.PascalUnicodeDataType;

public class CreatePatchedUnicodeStringValues extends GhidraScript {
  public void run() throws Exception {
    var memory = currentProgram.getMemory();
    var start = toAddr(0x30000);
    memory.createInitializedBlock("patched_unicode", start, 131072, (byte) 'a', monitor, false);
    memory.setShort(start, (short) 1);
    createData(start, PascalUnicodeDataType.dataType);
    // The data unit remains four bytes long while its value now consumes 128 KiB.
    memory.setShort(start, (short) 0xffff);
  }
}
