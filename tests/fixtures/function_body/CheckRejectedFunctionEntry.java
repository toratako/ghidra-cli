import ghidra.app.script.GhidraScript;

public class CheckRejectedFunctionEntry extends GhidraScript {
  public void run() {
    if (getInstructionAt(toAddr(0x1008)) != null) {
      throw new IllegalStateException("Automatic disassembly escaped the rejected request");
    }
  }
}
