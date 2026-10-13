import ghidra.app.script.GhidraScript;
import ghidra.framework.data.DefaultProjectData;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.ProjectLocator;
import java.nio.file.Path;

public class CreateExternalGarLink extends GhidraScript {
  public void run() throws Exception {
    Path path = Path.of(getScriptArgs()[0]);
    // Only read the link source; writable open would race the removal below
    // with Ghidra's asynchronous database cleanup after close().
    var external =
        new DefaultProjectData(
            new ProjectLocator(path.getParent().toString(), path.getFileName().toString()),
            false,
            false);
    try {
      var file = external.getRootFolder().getFile(getScriptArgs()[1]);
      var destination =
          state.getProject().getProjectData().getRootFolder().createFolder("external");
      try {
        DomainFile.class
            .getMethod("copyToAsLink", DomainFolder.class, boolean.class)
            .invoke(file, destination, false);
      } catch (NoSuchMethodException olderGhidra) {
        DomainFile.class.getMethod("copyToAsLink", DomainFolder.class).invoke(file, destination);
      }
    } finally {
      external.close();
    }
  }
}
