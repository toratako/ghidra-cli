
import ghidra.app.script.GhidraScript;
public class SemanticTypeUsesCapabilities extends GhidraScript {
    public void run() {
        try {
            Class.forName("ghidra.app.decompiler.ClangBitFieldToken");
            println("true");
        } catch (ClassNotFoundException unsupported) { println("false"); }
    }
}
