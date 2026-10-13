import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;

public class CreateSearchSpacesFixture extends GhidraScript {
  public void run() throws Exception {
    var language =
        DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:32:default"));
    var program =
        new ProgramDB(getScriptArgs()[0], language, language.getDefaultCompilerSpec(), this);
    try {
      int tx = program.startTransaction("search spaces fixture");
      try {
        var space = program.getAddressFactory().getDefaultAddressSpace();
        program
            .getMemory()
            .createInitializedBlock("end", space.getMaxAddress(), 1, (byte) 'X', monitor, false);
        program
            .getMemory()
            .createInitializedBlock(
                "later", space.getAddress(0x1000), 1, (byte) 'X', monitor, true);
      } finally {
        program.endTransaction(tx, true);
      }
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
