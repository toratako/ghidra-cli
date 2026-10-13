import ghidra.app.script.GhidraScript;
import ghidra.program.database.DataTypeArchiveDB;

public class CheckDeletionArchives extends GhidraScript {
  public void run() throws Exception {
    var project = state.getProject().getProjectData();
    for (String path : new String[] {"/types.gdt", "/archives/types.gdt"}) {
      var file = project.getFile(path);
      if (file == null || !DataTypeArchiveDB.class.isAssignableFrom(file.getDomainObjectClass()))
        throw new IllegalStateException("Deletion changed the archive: " + path);
    }
  }
}
