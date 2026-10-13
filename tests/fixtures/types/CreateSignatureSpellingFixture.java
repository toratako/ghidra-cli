import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;

public class CreateSignatureSpellingFixture extends GhidraScript {
  public void run() throws Exception {
    var address = toAddr(0x1000);
    currentProgram
        .getMemory()
        .createInitializedBlock("code", address, 16, (byte) 0, monitor, false);
    currentProgram
        .getFunctionManager()
        .createFunction(
            "lookup", address, new AddressSet(address, address.add(15)), SourceType.USER_DEFINED);
  }
}
