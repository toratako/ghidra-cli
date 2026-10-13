import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;

public class WarmTagUsageCache extends GhidraScript {
  public void run() throws Exception {
    var address = toAddr(0x3000);
    currentProgram
        .getFunctionManager()
        .createFunction(
            "unmapped_tagged", address, new AddressSet(address, address), SourceType.USER_DEFINED)
        .addTag("review");
    var manager = currentProgram.getFunctionManager().getFunctionTagManager();
    var tag = manager.getFunctionTag("review");
    if (manager.getUseCount(tag) != 4) {
      throw new IllegalStateException("Native fixture must have four tag memberships");
    }
  }
}
