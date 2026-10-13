
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
public class CreateExpressionNamedType extends GhidraScript {
    public void run() throws Exception {
        var dtm = currentProgram.getDataTypeManager();
        dtm.addDataType(new StructureDataType(CategoryPath.ROOT, "ExprBase", 1, dtm), null);
        dtm.addDataType(new StructureDataType(CategoryPath.ROOT, "ExprBase *", 3, dtm), null);
        dtm.addDataType(new StructureDataType(CategoryPath.ROOT,
            "DeepLiteral" + "*".repeat(129), 5, dtm), null);
    }
}
