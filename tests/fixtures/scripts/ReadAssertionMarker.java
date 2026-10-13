
import ghidra.app.script.GhidraScript;
public class ReadAssertionMarker extends GhidraScript {
    public void run() {
        println(currentProgram.getOptions("DiagnosticTest").getString("assertion_marker", "missing"));
    }
}
