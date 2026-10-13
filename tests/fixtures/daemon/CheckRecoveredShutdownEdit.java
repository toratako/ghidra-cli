
import ghidra.app.script.GhidraScript;
public class CheckRecoveredShutdownEdit extends GhidraScript {
    public void run() throws Exception {
        println("edit-count:" + currentProgram.getOptions("AutoSaveTest").getInt(getScriptArgs()[0], 0));
    }
}
