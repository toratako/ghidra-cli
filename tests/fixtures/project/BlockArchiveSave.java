
import ghidra.app.script.GhidraScript;
public class BlockArchiveSave extends GhidraScript {
    public void run() throws Exception {
        println(Integer.toString(currentProgram.startTransaction("hold archive save")));
    }
}
