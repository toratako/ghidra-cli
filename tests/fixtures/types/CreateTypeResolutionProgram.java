import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;

public class CreateTypeResolutionProgram extends GhidraScript {
  public void run() throws Exception {
    var language =
        DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(getScriptArgs()[1]));
    var program =
        new ProgramDB(getScriptArgs()[0], language, language.getDefaultCompilerSpec(), this);
    try {
      int tx = program.startTransaction("type resolution fixture");
      try {
        var dtm = program.getDataTypeManager();
        var hook = new FunctionDefinitionDataType(new CategoryPath("/Recovered"), "Hook", dtm);
        hook.setReturnType(VoidDataType.dataType);
        dtm.addDataType(hook, null);
        dtm.addDataType(new StructureDataType(CategoryPath.ROOT, "Holder", 0, dtm), null);
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
