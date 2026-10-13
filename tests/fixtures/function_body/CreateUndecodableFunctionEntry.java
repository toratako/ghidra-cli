import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.SourceType;

public class CreateUndecodableFunctionEntry extends GhidraScript {
  public void run() throws Exception {
    var address = toAddr(0x3000);
    // A two-byte x86 opcode with no second byte cannot be disassembled.
    currentProgram
        .getMemory()
        .createInitializedBlock("undecodable", address, 1, (byte) 0x0f, monitor, false);
    currentProgram.getSymbolTable().createLabel(address, "saved_entry", SourceType.USER_DEFINED);
  }
}
