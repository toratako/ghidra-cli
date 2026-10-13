
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
public class CreateResizeComponentOverflow extends GhidraScript {
    public void run() throws Exception {
        var dtm = currentProgram.getDataTypeManager();
        var bits = new StructureDataType(CategoryPath.ROOT, "BitCount", 1, dtm);
        bits.insertBitFieldAt(0, 1, 0, ByteDataType.dataType, 2, "low", null);
        bits.insertBitFieldAt(0, 1, 2, ByteDataType.dataType, 2, "high", null);
        dtm.addDataType(bits, null);
    }
}
