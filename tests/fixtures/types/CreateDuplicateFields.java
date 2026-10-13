
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
public class CreateDuplicateFields extends GhidraScript {
    public void run() throws Exception {
        var dtm = currentProgram.getDataTypeManager();
        String prefix = getScriptArgs()[0];
        var structure = new StructureDataType(CategoryPath.ROOT, prefix + "Struct", 0, dtm);
        structure.add(ByteDataType.dataType, "same", null);
        structure.add(ByteDataType.dataType, "same", null);
        dtm.addDataType(structure, null);
        var union = new UnionDataType(CategoryPath.ROOT, prefix + "Union", dtm);
        union.add(ByteDataType.dataType, "same", null);
        union.add(WordDataType.dataType, "same", null);
        dtm.addDataType(union, null);
    }
}
