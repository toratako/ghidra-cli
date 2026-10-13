import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;

public class CreateSearchLimitFixture extends GhidraScript {
  public void run() throws Exception {
    var language =
        DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
    var program =
        new ProgramDB(getScriptArgs()[0], language, language.getDefaultCompilerSpec(), this);
    try {
      int tx = program.startTransaction("search limits fixture");
      try {
        var space = program.getAddressFactory().getDefaultAddressSpace();
        for (long base : new long[] {0x1000, 0x8000, 0x10000}) {
          program
              .getMemory()
              .createInitializedBlock(
                  "block_" + base, space.getAddress(base), 160 * 32, (byte) 0, monitor, false);
        }
        for (int i = 0; i < 160; i++) {
          for (boolean defined : new boolean[] {false, true}) {
            var address = space.getAddress((defined ? 0x8000 : 0x1000) + i * 32);
            byte[] value =
                String.format(
                        java.util.Locale.ROOT,
                        (defined ? "DEFINED_NEEDLE_" : "CAP_NEEDLE_") + "%03d",
                        i)
                    .getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            program.getMemory().setBytes(address, value);
            if (defined)
              program.getListing().createData(address, StringDataType.dataType, value.length + 1);
          }
          var entry = space.getAddress(0x10000 + i * 16);
          program
              .getFunctionManager()
              .createFunction(
                  String.format(java.util.Locale.ROOT, "password_case_%03d", i),
                  entry,
                  new AddressSet(entry),
                  SourceType.USER_DEFINED);
          program
              .getReferenceManager()
              .addMemoryReference(
                  entry, space.getAddress(0x8000), RefType.DATA, SourceType.USER_DEFINED, 0);
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
