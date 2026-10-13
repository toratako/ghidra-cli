import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;

public class CreateUnionAlignmentCases extends GhidraScript {
  public void run() throws Exception {
    var dtm = currentProgram.getDataTypeManager();
    int address = 0x1000;
    for (String name : new String[] {"AlignAppend", "AlignSet"}) {
      var union = new UnionDataType(CategoryPath.ROOT, name, dtm);
      union.setPackingEnabled(true);
      union.add(new ArrayDataType(ByteDataType.dataType, 8, -1, dtm), "raw", null);
      var saved = dtm.addDataType(union, null);
      var holder = new StructureDataType(name + "Holder", 0, dtm);
      holder.setPackingEnabled(true);
      holder.add(ByteDataType.dataType, "prefix", null);
      holder.add(saved, "payload", null);
      holder.add(ByteDataType.dataType, "tail", null);
      var parent = dtm.addDataType(holder, null);
      if (parent.getLength() != 10 || saved.getAlignment() != 1)
        throw new IllegalStateException("Unexpected initial union alignment");
      currentProgram
          .getMemory()
          .createInitializedBlock(name, toAddr(address), 10, (byte) 0, monitor, false);
      currentProgram.getListing().createData(toAddr(address), parent);
      address += 0x100;
    }
  }
}
