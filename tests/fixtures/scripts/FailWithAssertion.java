
import ghidra.app.script.GhidraScript;
public class FailWithAssertion extends GhidraScript {
    public void run() {
        currentProgram.getOptions("DiagnosticTest").setString("assertion_marker", getScriptArgs()[0]);
        println("before assertion");
        throw new AssertionError("intentional script assertion");
    }
}
