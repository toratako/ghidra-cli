import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.Union;

public class CheckMultiReplacement extends GhidraScript {
  public void run() throws Exception {
    var dtm = currentProgram.getDataTypeManager();
    var holder = (Structure) dtm.getDataType("/Holder");
    var wrapper = (Structure) dtm.getDataType("/Wrapper");
    var applied = currentProgram.getListing().getDefinedDataAt(toAddr(0x1000));
    if (holder.getLength() != 16
        || !"left".equals(holder.getComponent(0).getFieldName())
        || !"right".equals(holder.getComponent(1).getFieldName())
        || wrapper.getComponent(1).getOffset() != 16
        || applied == null
        || applied.getLength() != wrapper.getLength()
        || applied.getComponent(0).getLength() != 16)
      throw new IllegalStateException("Import did not propagate complete replacement layouts");
    var morph = dtm.getDataType("/Morph");
    if (!(morph instanceof Union)
        || ((Structure) dtm.getDataType("/MorphHolder")).getComponent(0).getDataType() != morph
        || currentProgram.getListing().getDefinedDataAt(toAddr(0x1030)).getDataType() != morph)
      throw new IllegalStateException(
          "Import did not preserve uses of a replacement type identity");
  }
}
