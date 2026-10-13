import ghidra.app.script.GhidraScript;

public class PersistJarComment extends GhidraScript {
  public void run() throws Exception {
    setEOLComment(toAddr(getScriptArgs()[0]), "standalone JAR persisted comment");
  }
}
