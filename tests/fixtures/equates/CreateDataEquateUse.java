import ghidra.app.script.GhidraScript;

public class CreateDataEquateUse extends GhidraScript {
  public void run() throws Exception {
    var address = toAddr(0x1800);
    if (currentProgram.getListing().getDefinedDataAt(address) == null) {
      throw new IllegalStateException("Fixture requires defined data");
    }
    currentProgram.getEquateTable().createEquate("NATIVE_DATA", 0).addReference(address, 0);
  }
}
