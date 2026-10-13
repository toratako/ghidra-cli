import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;

public class CreateStorageFunction extends GhidraScript {
  public void run() throws Exception {
    var address = toAddr(0x1000);
    currentProgram
        .getFunctionManager()
        .createFunction(
            "entry", address, new AddressSet(address, address), SourceType.USER_DEFINED);
  }
}
