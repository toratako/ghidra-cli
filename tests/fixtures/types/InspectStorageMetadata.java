import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.SourceType;

public class InspectStorageMetadata extends GhidraScript {
  public void run() throws Exception {
    var function = getFunctionAt(toAddr(0x1100));
    var parameter = function.getParameter(1);
    if (!"preserved parameter comment".equals(parameter.getComment())
        || parameter.getSource() != SourceType.IMPORTED
        || function.getLocalVariables().length != 3
        || function.getStackPurgeSize() != 4
        || function.getStackFrame().getReturnAddressOffset() != 8)
      throw new IllegalStateException("Partial edit changed unrelated metadata");
  }
}
