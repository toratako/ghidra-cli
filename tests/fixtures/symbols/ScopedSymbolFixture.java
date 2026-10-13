import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;

public class ScopedSymbolFixture extends GhidraScript {
  public void run() throws Exception {
    String[] a = getScriptArgs();
    SymbolTable st = currentProgram.getSymbolTable();
    for (int i = 0; i < 2; i++) {
      Namespace ns =
          st.createNameSpace(
              currentProgram.getGlobalNamespace(), a[1] + i, SourceType.USER_DEFINED);
      st.createLabel(toAddr(a[0]), a[1], ns, SourceType.USER_DEFINED);
    }
  }
}
