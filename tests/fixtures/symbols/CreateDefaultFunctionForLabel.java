import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;

public class CreateDefaultFunctionForLabel extends GhidraScript {
  public void run() throws Exception {
    var entry = toAddr(0x1020);
    currentProgram
        .getFunctionManager()
        .createFunction(null, entry, new AddressSet(entry, entry), SourceType.DEFAULT);
  }
}
