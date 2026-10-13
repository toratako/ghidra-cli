
import ghidra.app.script.GhidraScript;
public class ReadCommentStackSpace extends GhidraScript {
    public void run() {
        println(currentProgram.getAddressFactory().getStackSpace().getName()
            + ":0xfffffffffffffff0");
    }
}
