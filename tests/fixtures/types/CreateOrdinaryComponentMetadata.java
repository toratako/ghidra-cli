
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
public class CreateOrdinaryComponentMetadata extends GhidraScript {
    public void run() throws Exception {
        var dtm = currentProgram.getDataTypeManager();
        var path = new CategoryPath("/Layout");
        var structure = new StructureDataType(path, "OrdinaryStruct", 10, dtm);
        structure.replaceAtOffset(0, DWordDataType.dataType, 4, "word", "word comment");
        structure.replaceAtOffset(8, ByteDataType.dataType, 1, null, "anonymous byte");
        dtm.addDataType(structure, null);
        var union = new UnionDataType(path, "OrdinaryUnion", dtm);
        union.add(DWordDataType.dataType, "word", "word comment");
        union.add(ByteDataType.dataType, null, "anonymous byte");
        dtm.addDataType(union, null);
    }
}
