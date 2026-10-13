import ghidra.app.script.GhidraScript;

public class CheckDeletedCopy extends GhidraScript {
  public void run() throws Exception {
    if (!currentProgram.getDomainFile().getPathname().equals("/" + getScriptArgs()[0]))
      throw new IllegalStateException("Deletion changed the selected file");
    if (state.getProject().getProjectData().getFile("/copies/closed") != null)
      throw new IllegalStateException("Deleted file still exists");
  }
}
