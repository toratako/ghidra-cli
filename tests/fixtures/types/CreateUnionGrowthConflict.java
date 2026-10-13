import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;

public class CreateUnionGrowthConflict extends GhidraScript {
  public void run() throws Exception {
    var dtm = currentProgram.getDataTypeManager();
    var member = new UnionDataType(CategoryPath.ROOT, "GrowingUnion", dtm);
    member.add(DWordDataType.dataType, "value", null);
    var saved = dtm.addDataType(member, null);
    var parent = new StructureDataType(CategoryPath.ROOT, "UnionParent", 8, dtm);
    parent.replaceAtOffset(0, saved, 4, "member", null);
    parent.replaceAtOffset(4, DWordDataType.dataType, 4, "tail", null);
    dtm.addDataType(parent, null);
  }
}
