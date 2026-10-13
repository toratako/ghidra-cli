import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;

public class CreateBitRemovalCountFixture extends GhidraScript {
  public void run() throws Exception {
    var dtm = currentProgram.getDataTypeManager();
    var structure = new StructureDataType("RemovalCountBits", 4, dtm);
    structure.insertBitFieldAt(0, 4, 0, UnsignedIntegerDataType.dataType, 3, "first", null);
    structure.insertBitFieldAt(0, 4, 3, UnsignedIntegerDataType.dataType, 3, "second", null);
    structure.insertBitFieldAt(0, 4, 7, UnsignedIntegerDataType.dataType, 25, "wide", "keep");
    structure.growStructure(Integer.MAX_VALUE - 4);
    var saved = (Structure) dtm.addDataType(structure, null);
    if (saved.getNumComponents() != Integer.MAX_VALUE - 1)
      throw new IllegalStateException("Fixture component count is invalid");
  }
}
