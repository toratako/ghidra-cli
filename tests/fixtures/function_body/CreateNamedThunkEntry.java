import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.SourceType;

public class CreateNamedThunkEntry extends GhidraScript {
  public void run() throws Exception {
    currentProgram.getMemory().setBytes(toAddr(0x1080), new byte[] {(byte) 0xe9, 0x7b, 0, 0, 0});
    currentProgram
        .getSymbolTable()
        .createLabel(toAddr(0x1080), "previous_label", SourceType.USER_DEFINED);
  }
}
