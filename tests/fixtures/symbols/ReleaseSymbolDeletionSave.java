import ghidra.app.script.GhidraScript;

public class ReleaseSymbolDeletionSave extends GhidraScript {
  public void run() throws Exception {
    currentProgram.endTransaction(Integer.parseInt(getScriptArgs()[0]), true);
  }
}
