import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.Structure;

public class CheckCImportNamespaceCollision extends GhidraScript {
  public void run() throws Exception {
    var manager = currentProgram.getDataTypeManager();
    var item = (Structure) manager.getDataType("/Item");
    var holder = (Structure) manager.getDataType("/Holder");
    var start = toAddr(0x1000);
    if (getScriptArgs()[0].equals("setup")) {
      currentProgram
          .getMemory()
          .createInitializedBlock("data", start, 32, (byte) 0, monitor, false);
      currentProgram.getListing().createData(start, item);
      currentProgram.getListing().createData(start.add(16), holder);
      return;
    }
    if (item.getLength() != 8
        || !item.getComponent(0).getFieldName().equals("original")
        || holder.getComponent(0).getDataType() != item)
      throw new IllegalStateException("Saved definitions or Holder reference changed");
    var itemData = currentProgram.getListing().getDefinedDataAt(start);
    var holderData = currentProgram.getListing().getDefinedDataAt(start.add(16));
    if (itemData == null
        || itemData.getLength() != 8
        || itemData.getDataType() != item
        || holderData == null
        || holderData.getLength() != 8
        || holderData.getComponent(0).getDataType() != item)
      throw new IllegalStateException("Applied data changed after rejected C import");
  }
}
