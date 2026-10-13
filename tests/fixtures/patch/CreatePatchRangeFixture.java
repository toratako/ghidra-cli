import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;

public class CreatePatchRangeFixture extends GhidraScript {
  public void run() throws Exception {
    var language =
        DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
    var program =
        new ProgramDB(getScriptArgs()[0], language, language.getDefaultCompilerSpec(), this);
    try {
      int tx = program.startTransaction("patch range fixture");
      try {
        var space = program.getAddressFactory().getDefaultAddressSpace();
        for (long offset : new long[] {0x1000, 0x2000, 0x3000, 0x3002, 0x4000, 0x4002}) {
          var block =
              program
                  .getMemory()
                  .createInitializedBlock(
                      "code" + offset, space.getAddress(offset), 2, (byte) 0x90, monitor, false);
          block.setExecute(true);
          block.setWrite(false);
        }
        program
            .getMemory()
            .createUninitializedBlock("uninitialized", space.getAddress(0x2002), 2, false);
        program.getMemory().setByte(space.getAddress(0x4001), (byte) 0xc3);
        program.getMemory().setByte(space.getAddress(0x4003), (byte) 0xc3);
        var alias =
            program
                .getMemory()
                .createByteMappedBlock(
                    "alias", space.getAddress(0x5000), space.getAddress(0x4002), 2, false);
        alias.setExecute(true);
        alias.setWrite(false);
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
