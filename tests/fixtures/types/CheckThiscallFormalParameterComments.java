import ghidra.app.script.GhidraScript;

public class CheckThiscallFormalParameterComments extends GhidraScript {
  public void run() throws Exception {
    var function = getFunctionAt(toAddr(0x1100));
    if (!"saved explicit object".equals(function.getParameter(1).getComment())
        || !"saved count".equals(function.getParameter(2).getComment()))
      throw new IllegalStateException("Convention edit lost retained formal parameter comments");
  }
}
