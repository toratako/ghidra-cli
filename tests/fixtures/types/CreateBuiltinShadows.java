
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.StructureDataType;
public class CreateBuiltinShadows extends GhidraScript {
    public void run() throws Exception {
        var dtm = currentProgram.getDataTypeManager();
        var category = new CategoryPath("/Shadows");
        dtm.addDataType(new StructureDataType(category, "uint32_t", 7, dtm), null);
        dtm.addDataType(new StructureDataType(category, "byte", 3, dtm), null);
    }
}
