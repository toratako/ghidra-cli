
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
public class CreateExistingOverwideDependency extends GhidraScript {
    public void run() throws Exception {
        var dtm = currentProgram.getDataTypeManager();
        var existing = new StructureDataType(new CategoryPath("/Source"), "ExistingOverwide", 0, dtm);
        existing.setPackingEnabled(true);
        existing.addBitField(UnsignedIntegerDataType.dataType, 64, "bits", null);
        var stored = dtm.addDataType(existing, null);
        var parent = new StructureDataType("ExistingContainer", 0, dtm);
        parent.add(stored, "value", null);
        dtm.addDataType(parent, null);
    }
}
