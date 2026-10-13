import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;

public class RestoreFunctionFixture extends GhidraScript {
  public void run() throws Exception {
    String[] a = getScriptArgs();
    for (int i = 0; i < 2; i++) {
      getFunctionAt(toAddr(a[i])).setParentNamespace(currentProgram.getGlobalNamespace());
      getFunctionAt(toAddr(a[i])).setName(a[i + 2], SourceType.USER_DEFINED);
    }
  }
}
