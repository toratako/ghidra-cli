
import ghidra.app.script.GhidraScript;
public class AllowAutoSave extends GhidraScript {
    public void run() throws Exception {
        currentProgram.endTransaction(Integer.parseInt(getScriptArgs()[0]), true);
        println("edit-count:" + currentProgram.getOptions("AutoSaveTest").getInt(getScriptArgs()[1], 0));
    }
}
