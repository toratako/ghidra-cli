import ghidra.app.script.GhidraScript;
import java.util.Locale;

public class QueryTestLocale extends GhidraScript {
  public void run() {
    writer.println(Locale.getDefault().toLanguageTag());
    Locale.setDefault(Locale.forLanguageTag(getScriptArgs()[0]));
  }
}
