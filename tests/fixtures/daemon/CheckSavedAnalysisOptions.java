import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;

public class CheckSavedAnalysisOptions extends GhidraScript {
  public void run() throws Exception {
    Object consumer = new Object();
    Program saved =
        (Program)
            currentProgram
                .getDomainFile()
                .getReadOnlyDomainObject(consumer, DomainFile.DEFAULT_VERSION, monitor);
    try {
      var options = saved.getOptions(Program.ANALYSIS_PROPERTIES);
      if (options.getBoolean("CLI Test.Boolean", true)
          || options.getInt("CLI Test.Int", 0) != -42
          || options.getLong("CLI Test.Long", 0) != Long.MAX_VALUE
          || options.getFloat("CLI Test.Float", 0) != 1.25f
          || options.getDouble("CLI Test.Double", 0) != 1.125d
          || !options.getString("CLI Test.String", "bad").isEmpty()
          || options.getEnum("CLI Test.Enum", SourceType.DEFAULT) != SourceType.USER_DEFINED
          || !options.getFile("CLI Test.File", null).equals(new java.io.File(getScriptArgs()[0]))
          || options.contains("CLI Test.Unknown")) {
        throw new IllegalStateException("Saved analysis option values or types differ");
      }
    } finally {
      saved.release(consumer);
    }
  }
}
