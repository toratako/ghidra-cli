import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;

public class CheckMovedTypeReferences extends GhidraScript {
  public void run() throws Exception {
    var dtm = currentProgram.getDataTypeManager();
    var alias = (TypeDef) dtm.getDataType("/ItemAlias");
    var moved = dtm.getDataType("/Final/MovedItem");
    if (((Pointer) alias.getDataType()).getDataType() != moved)
      throw new IllegalStateException("Moving type changed references");
    if (dtm.getCategory(new CategoryPath("/Draft/Empty")) != null
        || dtm.getCategory(new CategoryPath("/Missing")) != null
        || dtm.getCategory(new CategoryPath("/Bad")) != null)
      throw new IllegalStateException("Rejected category mutation persisted");
  }
}
