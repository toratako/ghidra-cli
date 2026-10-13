
import ghidra.app.script.GhidraScript;
public class PreventSymbolDeletionSave extends GhidraScript {
    public void run() throws Exception {
        println(Integer.toString(currentProgram.startTransaction("hold deletion save")));
    }
}
