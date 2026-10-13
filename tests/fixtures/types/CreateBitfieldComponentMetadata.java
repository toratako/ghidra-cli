
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
public class CreateBitfieldComponentMetadata extends GhidraScript {
    public void run() throws Exception {
        var dtm = currentProgram.getDataTypeManager();
        var path = new CategoryPath("/Layout");
        var word = dtm.addDataType(new TypedefDataType(path, "Word",
            UnsignedIntegerDataType.dataType, dtm), null);
        var structure = new StructureDataType(path, "BitLayout", 4, dtm);
        structure.insertBitFieldAt(0, 4, 0, word, 3, "low", "low three bits");
        structure.insertBitFieldAt(0, 4, 3, word, 10, "cross", "crosses a byte");
        structure.insertBitFieldAt(0, 4, 13, word, 3, null, "unnamed bits");
        dtm.addDataType(structure, null);
        var union = new UnionDataType(path, "BitUnion", dtm);
        union.addBitField(word, 3, "flags", "union flags");
        union.add(word, "raw", null);
        dtm.addDataType(union, null);
        var zero = new StructureDataType(path, "ZeroWidth", 0, dtm);
        zero.setPackingEnabled(true);
        zero.addBitField(word, 3, "before", null);
        zero.addBitField(word, 0, null, "alignment boundary");
        zero.addBitField(word, 4, "after", null);
        dtm.addDataType(zero, null);
        var clipped = new StructureDataType(path, "Clipped", 0, dtm);
        clipped.insertBitFieldAt(0, 1, 0, UnsignedCharDataType.dataType, 12, "clipped", null);
        dtm.addDataType(clipped, null);
    }
}
