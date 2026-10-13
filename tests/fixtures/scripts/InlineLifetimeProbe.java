import ghidra.app.script.GhidraScript;
import java.nio.file.Files;
import java.nio.file.Path;

public class InlineLifetimeProbe extends GhidraScript {
    public void run() throws Exception {
        String mode = getScriptArgs()[0];
        println("inline lifetime " + mode);
        if (mode.endsWith("leftover")) {
            Path output = Path.of(getSourceFile().getParentFile().getAbsolutePath()).resolve("preserved.txt");
            Files.writeString(output, "script-owned output");
        }
        if (mode.startsWith("throw")) throw new IllegalStateException("lifetime probe failure");
        if (mode.equals("cancel")) {
            monitor.cancel();
            monitor.checkCancelled();
        }
    }
}
