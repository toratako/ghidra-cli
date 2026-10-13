
import ghidra.app.script.GhidraScript;
import java.nio.file.Files;
import java.nio.file.Path;
public class WriteOnRun extends GhidraScript {
    public void run() throws Exception {
        Files.writeString(Path.of(getScriptArgs()[0]), "ran");
    }
}
