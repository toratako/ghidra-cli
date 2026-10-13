import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;

public class CreateDataConflictFixture extends GhidraScript {
  public void run() throws Exception {
    var language =
        DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
    var program =
        new ProgramDB(getScriptArgs()[0], language, language.getDefaultCompilerSpec(), this);
    try {
      int tx = program.startTransaction("data conflicts");
      try {
        var start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
        program.getMemory().createInitializedBlock("storage", start, 32, (byte) 0, monitor, false);
        program.getListing().createData(start.add(2), WordDataType.dataType);
        program.getMemory().setBytes(start.add(0x12), new byte[] {0x66, (byte) 0x90});
        if (!new DisassembleCommand(start.add(0x12), null, false).applyTo(program, monitor)) {
          throw new IllegalStateException("Could not disassemble fixture");
        }
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
