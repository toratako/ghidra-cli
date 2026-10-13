import ghidra.app.script.GhidraScript;

public class AnnotateSignatureParameters extends GhidraScript {
  public void run() throws Exception {
    var function = getFunctionAt(toAddr(0x1000));
    for (var parameter : function.getParameters())
      parameter.setComment("retain " + parameter.getName());
  }
}
