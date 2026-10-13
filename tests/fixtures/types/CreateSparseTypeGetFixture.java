import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;

public class CreateSparseTypeGetFixture extends GhidraScript {
  public void run() throws Exception {
    var dtm = currentProgram.getDataTypeManager();
    for (int length : new int[] {Integer.MAX_VALUE, 8}) {
      String name = length == 8 ? "SmallSparseGet" : "HugeSparseGet";
      var structure = new StructureDataType(name, length, dtm);
      structure.replaceAtOffset(length - 4, DWordDataType.dataType, 4, "tail", "keep");
      var saved = (Structure) dtm.addDataType(structure, null);
      if (saved.getNumComponents() != length - 3)
        throw new IllegalStateException("Unexpected sparse component count");
    }
  }
}
