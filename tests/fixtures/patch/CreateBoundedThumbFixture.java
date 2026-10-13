import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;

public class CreateBoundedThumbFixture extends GhidraScript {
  public void run() throws Exception {
    var language =
        DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("ARM:LE:32:v8"));
    var program =
        new ProgramDB(getScriptArgs()[0], language, language.getDefaultCompilerSpec(), this);
    try {
      int tx = program.startTransaction("bounded Thumb fixture");
      try {
        byte[] bytes = {8, (byte) 0xbf, 1, 0x20, 0x70, 0x47}; // IT EQ; MOV R0,#1; BX LR
        var start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
        program
            .getMemory()
            .createInitializedBlock(
                "code",
                start,
                new java.io.ByteArrayInputStream(bytes),
                bytes.length,
                monitor,
                false)
            .setExecute(true);
        program
            .getProgramContext()
            .setValue(program.getRegister("TMode"), start, start.add(5), java.math.BigInteger.ONE);
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
