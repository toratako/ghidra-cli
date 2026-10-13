import ghidra.app.script.GhidraScript;

public class AnnotateReturnTypeFixture extends GhidraScript {
  public void run() throws Exception {
    getFunctionAt(toAddr(0x1100)).getParameter(0).setComment("retain explicit parameter comment");
  }
}
