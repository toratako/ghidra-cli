import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;

public class CreateFieldShrinkCountFixture extends GhidraScript {
  public void run() throws Exception {
    var dtm = currentProgram.getDataTypeManager();
    var structure = new StructureDataType("ShrinkCountFields", 8, dtm);
    structure.insertBitFieldAt(0, 1, 0, UnsignedIntegerDataType.dataType, 3, "first", null);
    structure.insertBitFieldAt(0, 1, 3, UnsignedIntegerDataType.dataType, 3, "second", null);
    structure.replaceAtOffset(4, DWordDataType.dataType, 4, "word", "keep");
    structure.growStructure(Integer.MAX_VALUE - 8);
    var saved = (Structure) dtm.addDataType(structure, null);
    if (saved.getNumComponents() != Integer.MAX_VALUE - 2)
      throw new IllegalStateException("Fixture component count is invalid");
  }
}
