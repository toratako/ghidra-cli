import ghidra.app.script.GhidraScript;

public class CopyBridgeProgram extends GhidraScript {
  public void run() throws Exception {
    var folder =
        state.getProject().getProjectData().getRootFolder().createFolder(getScriptArgs()[0]);
    currentProgram.getDomainFile().copyTo(folder, monitor).setName("alternate");
    currentProgram
        .getDomainFile()
        .copyTo(folder.createFolder("deeper"), monitor)
        .setName("alternate");
  }
}
