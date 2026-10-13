
import ghidra.app.script.GhidraScript;
public class CopyRequestTargetPrograms extends GhidraScript {
    public void run() throws Exception {
        var folder = state.getProject().getProjectData().getRootFolder().createFolder(getScriptArgs()[0]);
        for (String child : new String[] { "first", "second" }) {
            currentProgram.getDomainFile().copyTo(folder.createFolder(child), monitor).setName("same-name");
        }
    }
}
