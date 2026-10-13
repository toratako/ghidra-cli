import ghidra.app.script.GhidraScript;

public class CheckReturnTypeParameterComment extends GhidraScript {
  public void run() throws Exception {
    var parameter = getFunctionAt(toAddr(0x1100)).getParameter(0);
    if (!"retain explicit parameter comment".equals(parameter.getComment()))
      throw new IllegalStateException("Return edit lost explicit parameter comment");
  }
}
