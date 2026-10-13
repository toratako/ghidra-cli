import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;

public class RemoveAnalysisTestOptions extends GhidraScript {
  public void run() {
    var options = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
    for (String name : options.getOptionNames()) {
      if (name.startsWith("CLI Test.")) options.removeOption(name);
    }
  }
}
