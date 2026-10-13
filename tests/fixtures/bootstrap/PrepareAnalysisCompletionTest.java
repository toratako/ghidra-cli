
import ghidra.app.script.GhidraScript;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
public class PrepareAnalysisCompletionTest extends GhidraScript {
    public void run() throws Exception {
        var options = currentProgram.getOptions(Program.PROGRAM_INFO);
        options.removeOption(Program.ANALYZED_OPTION_NAME);
        String flag = getScriptArgs()[0];
        if (!flag.equals("missing")) options.setBoolean(Program.ANALYZED_OPTION_NAME, Boolean.parseBoolean(flag));
        if (Boolean.parseBoolean(getScriptArgs()[1])) {
            var analyzer = new AbstractAnalyzer("Cancel Completion Test", "Cancel analysis deterministically", AnalyzerType.BYTE_ANALYZER) {
                { setPriority(AnalysisPriority.HIGHEST_PRIORITY); }
                public boolean added(Program program, AddressSetView set, TaskMonitor taskMonitor, MessageLog log) {
                    taskMonitor.cancel();
                    return false;
                }
            };
            AutoAnalysisManager.getAnalysisManager(currentProgram)
                .scheduleOneTimeAnalysis(analyzer, currentProgram.getMemory());
        }
    }
}
