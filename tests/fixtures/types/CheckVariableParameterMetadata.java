import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.SourceType;

public class CheckVariableParameterMetadata extends GhidraScript {
  public void run() throws Exception {
    var parameter = getFunctionAt(toAddr(0x10a0)).getParameter(0);
    if (!"buffer".equals(parameter.getName())
        || parameter.getSource() != SourceType.USER_DEFINED
        || !"retain partially saved parameter".equals(parameter.getComment()))
      throw new IllegalStateException("Variable edit replaced existing parameter metadata");
  }
}
