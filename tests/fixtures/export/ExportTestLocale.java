
import ghidra.app.script.GhidraScript;
import java.util.Locale;
public class ExportTestLocale extends GhidraScript {
    public void run() {
        println(Locale.getDefault().toLanguageTag());
        Locale.setDefault(Locale.forLanguageTag(getScriptArgs()[0]));
    }
}
