
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
public class CreateConstrainedImportApplication extends GhidraScript {
    public void run() throws Exception {
        var dtm = currentProgram.getDataTypeManager();
        var imported = dtm.getDataType("/Imported");
        var holder = new StructureDataType(CategoryPath.ROOT, "ConstrainedHolder", 8, dtm);
        holder.replaceAtOffset(0, dtm.getDataType("/Embedded"), 4, "child", null);
        holder.replaceAtOffset(4, DWordDataType.dataType, 4, "tail", "keep");
        dtm.addDataType(holder, null);
        var address = toAddr(0x1000);
        currentProgram.getMemory().createInitializedBlock("data", address, 32, (byte) 0, monitor, false);
        currentProgram.getListing().createData(address, imported);
        currentProgram.getListing().createData(address.add(4), DWordDataType.dataType);
    }
}
