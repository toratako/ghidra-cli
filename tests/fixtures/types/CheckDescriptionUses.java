
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
public class CheckDescriptionUses extends GhidraScript {
    public void run() throws Exception {
        var dtm = currentProgram.getDataTypeManager();
        var node = dtm.getDataType("/Descriptions/Node");
        var choice = (Union) dtm.getDataType("/Descriptions/Choice");
        var holder = (Structure) dtm.getDataType("/Descriptions/Holder");
        if (((Pointer) holder.getComponent(0).getDataType()).getDataType() != node
                || ((Array) holder.getComponent(1).getDataType()).getDataType() != node
                || holder.getComponent(2).getDataType() != choice
                || holder.getComponent(3).getDataType() != dtm.getDataType("/Descriptions/Mode")
                || choice.getComponent(0).getDataType() != node
                || ((Pointer) choice.getComponent(1).getDataType()).getDataType() != node
                || ((TypeDef) dtm.getDataType("/Descriptions/Alias")).getBaseDataType() != node
                || currentProgram.getListing().getDataAt(toAddr(0x1000)).getDataType() != holder)
            throw new IllegalStateException("Description edit changed registered type uses");
    }
}
