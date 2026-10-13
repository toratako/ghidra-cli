import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.symbol.SourceType;

public class StorageMetadataFixture extends GhidraScript {
  public void run() throws Exception {
    var function = getFunctionAt(toAddr(0x1100));
    function.getParameter(1).setComment("preserved parameter comment");
    function.getParameter(1).getSymbol().setSource(SourceType.IMPORTED);
    var signature = new FunctionDefinitionDataType("local_override");
    signature.setReturnType(CharDataType.dataType);
    HighFunctionDBUtil.writeOverride(function, function.getEntryPoint(), signature);
  }
}
