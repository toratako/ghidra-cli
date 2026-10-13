import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class DuplicateFunctionFixture extends GhidraScript {
  public void run() throws Exception {
    String[] a = getScriptArgs();
    for (int i = 0; i < 2; i++) {
      Function f = getFunctionAt(toAddr(a[i]));
      if (!f.getParentNamespace().isGlobal())
        throw new IllegalStateException("fixture must be global");
    }
    for (int i = 0; i < 2; i++) {
      Function f = getFunctionAt(toAddr(a[i]));
      Namespace ns =
          currentProgram
              .getSymbolTable()
              .createNameSpace(
                  currentProgram.getGlobalNamespace(), a[2] + i, SourceType.USER_DEFINED);
      f.setParentNamespace(ns);
      f.setName(a[2], SourceType.USER_DEFINED);
    }
  }
}
