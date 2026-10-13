
import ghidra.app.script.GhidraScript;
public class CopyDeletionTargets extends GhidraScript {
    public void run() throws Exception {
        var root = state.getProject().getProjectData().getRootFolder();
        var folder = root.createFolder("copies");
        currentProgram.getDomainFile().copyTo(folder, monitor).setName("closed");
        currentProgram.getDomainFile().copyTo(folder, monitor).setName("later");
    }
}
