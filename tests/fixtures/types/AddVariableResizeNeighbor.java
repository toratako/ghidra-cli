
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.symbol.SourceType;
public class AddVariableResizeNeighbor extends GhidraScript {
    public void run() throws Exception {
        var function = getFunctionAt(toAddr(0x1000));
        for (var local : function.getLocalVariables()) {
            if (!"guarded".equals(local.getName()) || local.getStackOffset() != -8)
                throw new IllegalStateException("Unexpected stack-local layout");
        }
        function.addLocalVariable(new LocalVariableImpl("kept_neighbor", IntegerDataType.dataType,
            -4, currentProgram), SourceType.USER_DEFINED);
    }
}
