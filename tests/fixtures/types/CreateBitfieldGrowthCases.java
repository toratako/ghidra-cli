import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;

public class CreateBitfieldGrowthCases extends GhidraScript {
  public void run() throws Exception {
    var dtm = currentProgram.getDataTypeManager();
    for (String name : new String[] {"EmbeddedBits", "EdgeBits", "FreeBits"}) {
      var child = dtm.addDataType(new StructureDataType(name, 4, dtm), null);
      if (name.equals("EmbeddedBits")) {
        var parent = new StructureDataType("BitsParent", 8, dtm);
        parent.replaceAtOffset(0, child, 4, "child", null);
        parent.replaceAtOffset(4, DWordDataType.dataType, 4, "tail", "keep");
        dtm.addDataType(parent, null);
      } else if (name.equals("EdgeBits")) {
        currentProgram
            .getMemory()
            .createInitializedBlock("edge", toAddr(0x1000), 6, (byte) 0, monitor, false);
        currentProgram.getListing().createData(toAddr(0x1000), child);
      }
    }
  }
}
