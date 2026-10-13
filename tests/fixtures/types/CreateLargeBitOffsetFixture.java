import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;

public class CreateLargeBitOffsetFixture extends GhidraScript {
  public void run() throws Exception {
    var dtm = currentProgram.getDataTypeManager();
    var structure = new StructureDataType("HugeBits", 0x10000004, dtm);
    structure.replaceAtOffset(0x10000000, DWordDataType.dataType, 4, "tail", "keep");
    dtm.addDataType(structure, null);
  }
}
