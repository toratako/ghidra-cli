import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.Undefined4DataType;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.symbol.SourceType;

public class AddNumberedVariableGroup extends GhidraScript {
  public void run() throws Exception {
    var function = getFunctionAt(toAddr(0x1000));
    var type =
        Boolean.parseBoolean(getScriptArgs()[0])
            ? IntegerDataType.dataType
            : Undefined4DataType.dataType;
    function.addLocalVariable(
        new LocalVariableImpl("value", type, -8, currentProgram), SourceType.USER_DEFINED);
    function.addLocalVariable(
        new LocalVariableImpl(
            "value$1", 0x18, type, currentProgram.getRegister("EAX"), currentProgram),
        SourceType.USER_DEFINED);
  }
}
