
import ghidra.app.script.GhidraScript;
public class ReadSignatureProgramState extends GhidraScript {
    public void run() {
        println("program-state=" + currentProgram.getModificationNumber() + ":" + currentProgram.isChanged());
    }
}
