
import ghidra.app.script.GhidraScript;
public class ReadPointerProgramState extends GhidraScript {
    public void run() {
        println("program-state=" + currentProgram.getModificationNumber() + ":" + currentProgram.isChanged());
    }
}
