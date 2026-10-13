import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.Enum;

public class SetEnumMetadata extends GhidraScript {
  public void run() throws Exception {
    var type = (Enum) currentProgram.getDataTypeManager().getDataType("/Mode");
    type.setDescription("recovered mode");
    type.remove("Keep");
    type.add("Keep", 1, "alias remains");
    type.remove("Negative");
    type.add("Negative", -1, "signed member");
  }
}
