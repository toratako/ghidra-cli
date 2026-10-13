
import ghidra.app.script.GhidraScript;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
public class QueueAnalysisModesFixture extends GhidraScript {
    public void run() {
        String mode = getScriptArgs()[0];
        var space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        var manager = AutoAnalysisManager.getAnalysisManager(currentProgram);
        manager.blockAdded(new AddressSet(space.getAddress(0x2000), space.getAddress(0x20ff)));
        if (mode.equals("native")) return;
        var analyzer = new AbstractAnalyzer("CLI Analysis Mode Probe", "Deterministic native analysis work",
                AnalyzerType.BYTE_ANALYZER) {
            { setPriority(AnalysisPriority.HIGHEST_PRIORITY); }
            public boolean added(Program program, AddressSetView set, TaskMonitor taskMonitor, MessageLog log) {
                if (mode.equals("cancel")) {
                    program.getListing().setComment(space.getAddress(0x1000), CodeUnit.EOL_COMMENT, "saved-partial-analysis");
                    taskMonitor.cancel();
                    return false;
                }
                program.getListing().setComment(space.getAddress(0x3000), CodeUnit.EOL_COMMENT, "derived-analysis");
                // Enqueue fresh native work while draining this pass. Its seed
                // is outside both the CLI range and the earlier pending range.
                manager.blockAdded(new AddressSet(space.getAddress(0x3000), space.getAddress(0x30ff)));
                return true;
            }
        };
        manager.scheduleOneTimeAnalysis(analyzer, new AddressSet(space.getAddress(0x1000)));
    }
}
