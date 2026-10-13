
import ghidra.app.script.GhidraScript;
public class CheckBridgeCharset extends GhidraScript {
    public void run() {
        println(java.nio.charset.Charset.defaultCharset().name());
    }
}
