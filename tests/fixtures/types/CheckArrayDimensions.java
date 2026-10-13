
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.Structure;
public class CheckArrayDimensions extends GhidraScript {
    public void run() throws Exception {
        var holder = (Structure) currentProgram.getDataTypeManager().getDataType("/Holder");
        var outer = (Array) holder.getComponent(1).getDataType();
        var inner = (Array) outer.getDataType();
        if (outer.getNumElements() != 2 || inner.getNumElements() != 3)
            throw new IllegalStateException("Array dimensions were reversed");
    }
}
