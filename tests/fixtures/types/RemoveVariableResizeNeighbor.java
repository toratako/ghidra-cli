import ghidra.app.script.GhidraScript;

public class RemoveVariableResizeNeighbor extends GhidraScript {
  public void run() throws Exception {
    var function = getFunctionAt(toAddr(0x1000));
    for (var local : function.getLocalVariables()) {
      if ("kept_neighbor".equals(local.getName())) function.removeVariable(local);
    }
  }
}
