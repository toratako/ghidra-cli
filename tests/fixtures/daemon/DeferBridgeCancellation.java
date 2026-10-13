
import ghidra.app.script.GhidraScript;
import java.nio.file.Files;
import java.nio.file.Path;
public class DeferBridgeCancellation extends GhidraScript {
    public void run() throws Exception {
        monitor.setCancelEnabled(false);
        monitor.setMessage("waiting-with-cancel-disabled");
        long deadline = System.currentTimeMillis() + 30000;
        while (!Files.exists(Path.of(getScriptArgs()[0])) && System.currentTimeMillis() < deadline) {
            Thread.sleep(10);
        }
        monitor.setCancelEnabled(true);
        monitor.checkCancelled();
        throw new IllegalStateException("Cancellation was discarded");
    }
}
