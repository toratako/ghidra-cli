import ghidra.app.script.GhidraScript;
import ghidra.base.project.GhidraProject;
import java.nio.file.Files;
import java.nio.file.Path;

public class HoldExternalProject extends GhidraScript {
  public void run() throws Exception {
    String[] args = getScriptArgs();
    GhidraProject project = GhidraProject.openProject(args[0], args[1], false);
    try {
      project.openProgram("/", args[4], false);
      Files.writeString(Path.of(args[2]), "locked");
      long deadline = System.currentTimeMillis() + 120000;
      while (!Files.exists(Path.of(args[3]))) {
        if (System.currentTimeMillis() > deadline) {
          throw new IllegalStateException("External owner was not released");
        }
        Thread.sleep(20);
      }
    } finally {
      project.close();
    }
  }
}
