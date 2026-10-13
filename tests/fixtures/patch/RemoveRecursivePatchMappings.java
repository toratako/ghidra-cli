import ghidra.app.script.GhidraScript;

public class RemoveRecursivePatchMappings extends GhidraScript {
  public void run() throws Exception {
    var memory = currentProgram.getMemory();
    for (long address : new long[] {0x5000, 0x10000, 0x14000}) {
      memory.removeBlock(memory.getBlock(toAddr(address)), monitor);
    }
  }
}
