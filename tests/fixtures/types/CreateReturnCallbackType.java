
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.IntegerDataType;
public class CreateReturnCallbackType extends GhidraScript {
    public void run() throws Exception {
        var callback = new FunctionDefinitionDataType("ReturnCallback");
        callback.setReturnType(IntegerDataType.dataType);
        currentProgram.getDataTypeManager().addDataType(callback, null);
    }
}
