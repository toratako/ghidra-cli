import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.PointerDataType;

public class CheckCreationMappedPointer extends GhidraScript {
  public void run() throws Exception {
    var memory = currentProgram.getMemory();
    var address = toAddr(0x3000);
    if (getScriptArgs()[0].equals("create")) {
      memory.createByteMappedBlock("unbacked_view", address, toAddr(0x4000), 8, false);
      currentProgram
          .getListing()
          .createData(address, new PointerDataType(null, 8, currentProgram.getDataTypeManager()));
    }
    var data = currentProgram.getListing().getDefinedDataAt(address);
    if (data == null
        || data.getValue() != null
        || currentProgram.getReferenceManager().getReferencesFrom(address).length != 0)
      throw new IllegalStateException("Unbacked mapped pointer changed");
  }
}
