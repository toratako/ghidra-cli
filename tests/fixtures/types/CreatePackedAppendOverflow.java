import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;

public class CreatePackedAppendOverflow extends GhidraScript {
  public void run() throws Exception {
    var dtm = currentProgram.getDataTypeManager();
    var structure = new StructureDataType("PackedAppendOverflow", 0, dtm);
    structure.setPackingEnabled(true);
    structure.add(
        new ArrayDataType(ByteDataType.dataType, Integer.MAX_VALUE - 1, -1, dtm), "bytes", "keep");
    var saved = dtm.addDataType(structure, null);
    if (saved.getLength() != Integer.MAX_VALUE - 1)
      throw new IllegalStateException(
          "Fixture must leave one byte below the supported structure size");
  }
}
