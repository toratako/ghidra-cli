import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.PascalString255DataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;

public class CreatePascalExtentFixture extends GhidraScript {
  public void run() throws Exception {
    var language =
        DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:32:default"));
    var program =
        new ProgramDB(getScriptArgs()[0], language, language.getDefaultCompilerSpec(), this);
    try {
      int tx = program.startTransaction("Pascal string extent");
      try {
        var space = program.getAddressFactory().getDefaultAddressSpace();
        var valid = space.getAddress(0x1000);
        program
            .getMemory()
            .createInitializedBlock(
                "valid",
                valid,
                new java.io.ByteArrayInputStream(new byte[] {'l', 'i', 'v', 'e', 0}),
                5,
                monitor,
                false);
        program.getListing().createData(valid, StringDataType.dataType, 5);
        var pascal = space.getMaxAddress().subtract(1);
        program
            .getMemory()
            .createInitializedBlock(
                "pascal",
                pascal,
                new java.io.ByteArrayInputStream(new byte[] {1, 'x'}),
                2,
                monitor,
                false);
        program.getListing().createData(pascal, PascalString255DataType.dataType);
        // Editing the length prefix does not resize the applied data unit.
        program.getMemory().setByte(pascal, (byte) 0xff);
        program
            .getReferenceManager()
            .addMemoryReference(valid, valid, RefType.DATA, SourceType.USER_DEFINED, 0);
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
