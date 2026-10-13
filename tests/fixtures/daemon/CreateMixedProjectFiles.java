
import ghidra.app.script.GhidraScript;
import ghidra.program.database.DataTypeArchiveDB;
public class CreateMixedProjectFiles extends GhidraScript {
    public void run() throws Exception {
        var root = state.getProject().getProjectData().getRootFolder();
        String name = getScriptArgs()[0];
        var folder = root.createFolder(name);
        for (var parent : new ghidra.framework.model.DomainFolder[] { root, folder }) {
            Object consumer = new Object();
            var archive = new DataTypeArchiveDB(parent, name + ".gdt", consumer);
            archive.release(consumer);
            if (parent.getFile(name + ".gdt") == null)
                throw new IllegalStateException("Archive fixture was not saved");
        }
        currentProgram.getDomainFile().copyTo(folder, monitor).setName("copy");
    }
}
