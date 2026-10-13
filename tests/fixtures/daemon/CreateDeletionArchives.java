
import ghidra.app.script.GhidraScript;
import ghidra.program.database.DataTypeArchiveDB;
public class CreateDeletionArchives extends GhidraScript {
    public void run() throws Exception {
        var root = state.getProject().getProjectData().getRootFolder();
        var folder = root.createFolder("archives");
        for (var parent : new ghidra.framework.model.DomainFolder[] { root, folder }) {
            Object consumer = new Object();
            var archive = new DataTypeArchiveDB(parent, "types.gdt", consumer);
            archive.release(consumer);
        }
    }
}
