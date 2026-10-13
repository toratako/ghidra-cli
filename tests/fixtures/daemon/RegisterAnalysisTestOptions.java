
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.OptionType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
public class RegisterAnalysisTestOptions extends GhidraScript {
    public void run() {
        var options = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
        options.registerOption("CLI Test.Boolean", true, null, "A nested boolean setting");
        options.registerOption("CLI Test.Int", 7, null, "An integer setting");
        options.registerOption("CLI Test.Long", 8L, null, "A long setting");
        options.registerOption("CLI Test.Float", 0.5f, null, "A float setting");
        options.registerOption("CLI Test.Double", 0.25d, null, "A double setting");
        options.registerOption("CLI Test.String", "original", null, "A string setting");
        options.registerOption("CLI Test.Enum", SourceType.DEFAULT, null, "An enum setting");
        options.registerOption("CLI Test.File", OptionType.FILE_TYPE, null, null, "A file setting");
        options.registerOption("CLI Test.Color", java.awt.Color.BLACK, null, "A UI setting");
    }
}
