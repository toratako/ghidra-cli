import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import java.io.File;

public class VerifyPackedExport extends GhidraScript {
  public void run() throws Exception {
    var root = state.getProject().getProjectData().getRootFolder();
    var file = root.createFile(getScriptArgs()[1], new File(getScriptArgs()[0]), monitor);
    Object consumer = new Object();
    try {
      Program reopened = (Program) file.getDomainObject(consumer, true, false, monitor);
      try {
        if (!reopened.getName().equals(currentProgram.getName())
            || reopened.getFunctionManager().getFunctionCount()
                != currentProgram.getFunctionManager().getFunctionCount()
            || reopened.getMemory().getSize() != currentProgram.getMemory().getSize()) {
          throw new IllegalStateException("Packed export differs from current program");
        }
      } finally {
        reopened.release(consumer);
      }
    } finally {
      file.delete();
    }
  }
}
