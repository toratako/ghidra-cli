
import ghidra.app.script.GhidraScript;
public class EditThenFailAutoSave extends GhidraScript {
    public void run() throws Exception {
        setEOLComment(toAddr(getScriptArgs()[0]), getScriptArgs()[1]);
        throw new IllegalStateException("intentional failure after editing");
    }
}
