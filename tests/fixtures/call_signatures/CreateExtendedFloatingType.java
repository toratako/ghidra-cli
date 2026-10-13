import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.Float10DataType;
import ghidra.program.model.data.TypedefDataType;

public class CreateExtendedFloatingType extends GhidraScript {
  public void run() throws Exception {
    var manager = currentProgram.getDataTypeManager();
    manager.addDataType(
        new TypedefDataType(
            new CategoryPath("/Recovered"), "ExtendedFloat", Float10DataType.dataType, manager),
        null);
  }
}
