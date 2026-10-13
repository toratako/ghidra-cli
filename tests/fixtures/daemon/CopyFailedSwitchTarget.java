
import ghidra.app.script.GhidraScript;
public class CopyFailedSwitchTarget extends GhidraScript {
    public void run() throws Exception {
        var folder = state.getProject().getProjectData().getRootFolder().createFolder(getScriptArgs()[0]);
        currentProgram.getDomainFile().copyTo(folder, monitor);
    }
}
