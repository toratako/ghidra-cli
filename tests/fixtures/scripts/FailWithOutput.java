
import ghidra.app.script.GhidraScript;
public class FailWithOutput extends GhidraScript {
    public void run() throws Exception {
        currentProgram.getOptions("DiagnosticTest").setString("marker", getScriptArgs()[0]);
        println("before failure");
        throw new IllegalStateException("intentional diagnostic failure");
    }
}
