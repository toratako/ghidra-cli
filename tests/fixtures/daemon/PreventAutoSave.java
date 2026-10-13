import ghidra.app.script.GhidraScript;

public class PreventAutoSave extends GhidraScript {
  public void run() throws Exception {
    var options = currentProgram.getOptions("AutoSaveTest");
    String key = getScriptArgs()[0];
    options.setInt(key, options.getInt(key, 0) + 1);
    println(Integer.toString(currentProgram.startTransaction("deliberately left open")));
  }
}
