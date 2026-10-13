import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;

public class CreateTemporaryProgram extends GhidraScript {
  public void run() throws Exception {
    var language = currentProgram.getLanguage();
    var program =
        new ProgramDB(getScriptArgs()[0], language, language.getDefaultCompilerSpec(), this);
    try {
      state
          .getProject()
          .getProjectData()
          .getRootFolder()
          .createFile(getScriptArgs()[0], program, monitor);
    } finally {
      program.release(this);
    }
  }
}
