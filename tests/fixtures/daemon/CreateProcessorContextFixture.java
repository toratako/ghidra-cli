import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;

public class CreateProcessorContextFixture extends GhidraScript {
  public void run() throws Exception {
    var language =
        DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("ARM:LE:32:v8"));
    var program =
        new ProgramDB(getScriptArgs()[0], language, language.getDefaultCompilerSpec(), this);
    try {
      int tx = program.startTransaction("processor context fixture");
      try {
        var space = program.getAddressFactory().getDefaultAddressSpace();
        // ARM MOV R0,#1; BX LR, and Thumb IT EQ; MOV R0,#1; BX LR.
        byte[] arm = {1, 0, (byte) 0xa0, (byte) 0xe3, 0x1e, (byte) 0xff, 0x2f, (byte) 0xe1};
        byte[] thumb = {8, (byte) 0xbf, 1, 0x20, 0x70, 0x47};
        program
            .getMemory()
            .createInitializedBlock(
                "arm",
                space.getAddress(0x1000),
                new java.io.ByteArrayInputStream(arm),
                arm.length,
                monitor,
                false)
            .setExecute(true);
        program
            .getMemory()
            .createInitializedBlock(
                "thumb",
                space.getAddress(0x2000),
                new java.io.ByteArrayInputStream(thumb),
                thumb.length,
                monitor,
                false)
            .setExecute(true);
        program
            .getMemory()
            .createInitializedBlock(
                "thumb_prefix", space.getAddress(0x1ff0), 0x10, (byte) 0, monitor, false);
        program
            .getMemory()
            .createInitializedBlock(
                "scratch", space.getAddress(0x3000), 0x40, (byte) 0, monitor, false);
        program
            .getMemory()
            .createInitializedBlock(
                "context_overlay", space.getAddress(0x3000), 0x40, (byte) 0, monitor, true);
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
