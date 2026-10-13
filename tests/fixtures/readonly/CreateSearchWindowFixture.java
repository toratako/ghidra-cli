import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;

public class CreateSearchWindowFixture extends GhidraScript {
  public void run() throws Exception {
    var language =
        DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
    var program =
        new ProgramDB(getScriptArgs()[0], language, language.getDefaultCompilerSpec(), this);
    try {
      int tx = program.startTransaction("search fixture");
      try {
        var space = program.getAddressFactory().getDefaultAddressSpace();
        String[] hex = {
          "50617373776f726400", // undefined Password
          "50617373776f726400", // defined Password
          "5261774f6e6c7900", // undefined RawOnly
          "e697a5e69cac", // 日本, UTF-8
          "e5652c67", // 日本, UTF-16LE
          "65e5672c", // 日本, UTF-16BE
          "93fa967b", // 日本, Shift_JIS
          "6161616161", // overlapping aa matches
          "58".repeat(300) // no implicit extraction window
        };
        for (int i = 0; i < hex.length; i++) {
          byte[] bytes = java.util.HexFormat.of().parseHex(hex[i]);
          var address = space.getAddress(0x1000 + i * 0x1000);
          program
              .getMemory()
              .createInitializedBlock(
                  "raw" + i,
                  address,
                  new java.io.ByteArrayInputStream(bytes),
                  bytes.length,
                  monitor,
                  false);
          if (i == 1)
            program
                .getListing()
                .createData(
                    address, ghidra.program.model.data.StringDataType.dataType, bytes.length);
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
