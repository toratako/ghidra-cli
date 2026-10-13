import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;

public class CreateMaximumBitComponentFixture extends GhidraScript {
  public void run() throws Exception {
    var dtm = currentProgram.getDataTypeManager();
    var structure = new StructureDataType("MaximumBits", Integer.MAX_VALUE, dtm);
    structure.insertBitFieldAt(0, 1, 0, UnsignedIntegerDataType.dataType, 3, "first", "keep");
    var saved = (Structure) dtm.addDataType(structure, null);
    if (saved.getNumComponents() != Integer.MAX_VALUE)
      throw new IllegalStateException("Fixture component count is invalid");
  }
}
