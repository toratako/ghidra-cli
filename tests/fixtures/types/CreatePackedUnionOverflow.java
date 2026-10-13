import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;

public class CreatePackedUnionOverflow extends GhidraScript {
  public void run() throws Exception {
    var dtm = currentProgram.getDataTypeManager();
    for (String name : new String[] {"PackedUnionAppend", "PackedUnionSet"}) {
      var union = new UnionDataType(CategoryPath.ROOT, name, dtm);
      union.setPackingEnabled(true);
      union.add(
          new ArrayDataType(ByteDataType.dataType, Integer.MAX_VALUE, -1, dtm), "bytes", "keep");
      if (name.equals("PackedUnionSet")) union.add(ByteDataType.dataType, "tag", "keep tag");
      var saved = dtm.addDataType(union, null);
      if (saved.getLength() != Integer.MAX_VALUE)
        throw new IllegalStateException("Fixture must fill the supported union size");
    }
  }
}
