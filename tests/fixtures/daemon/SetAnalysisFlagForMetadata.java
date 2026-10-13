
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
public class SetAnalysisFlagForMetadata extends GhidraScript {
    public void run() throws Exception {
        var options = currentProgram.getOptions(Program.PROGRAM_INFO);
        options.removeOption(Program.ANALYZED_OPTION_NAME);
        String flag = getScriptArgs()[0];
        if (flag.equals("invalid")) options.setString(Program.ANALYZED_OPTION_NAME, "unknown");
        else if (!flag.equals("missing")) options.setBoolean(Program.ANALYZED_OPTION_NAME, Boolean.parseBoolean(flag));
    }
}
