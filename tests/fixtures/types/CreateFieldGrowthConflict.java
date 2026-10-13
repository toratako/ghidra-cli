
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
public class CreateFieldGrowthConflict extends GhidraScript {
    public void run() throws Exception {
        var dtm = currentProgram.getDataTypeManager();
        var child = dtm.addDataType(new StructureDataType(CategoryPath.ROOT, "GrowingChild", 4, dtm), null);
        var parent = new StructureDataType(CategoryPath.ROOT, "ConstrainedParent", 8, dtm);
        parent.replaceAtOffset(0, child, 4, "child", null);
        parent.replaceAtOffset(4, DWordDataType.dataType, 4, "tail", null);
        dtm.addDataType(parent, null);
    }
}
