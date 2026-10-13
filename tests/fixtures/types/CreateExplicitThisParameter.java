import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;

public class CreateExplicitThisParameter extends GhidraScript {
  public void run() throws Exception {
    var function = getFunctionAt(toAddr(0x1100));
    function.replaceParameters(
        FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
        false,
        SourceType.USER_DEFINED,
        new ParameterImpl("this", new PointerDataType(IntegerDataType.dataType), currentProgram),
        new ParameterImpl("count", IntegerDataType.dataType, currentProgram));
    function.getParameter(0).setComment("saved explicit object");
    function.getParameter(1).setComment("saved count");
  }
}
