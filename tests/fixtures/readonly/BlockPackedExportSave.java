
import ghidra.app.script.GhidraScript;
public class BlockPackedExportSave extends GhidraScript {
    public void run() throws Exception {
        println(Integer.toString(currentProgram.startTransaction("block packed export save")));
    }
}
