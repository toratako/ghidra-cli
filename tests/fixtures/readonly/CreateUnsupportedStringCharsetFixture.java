import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.CharsetSettingsDefinition;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

public class CreateUnsupportedStringCharsetFixture extends GhidraScript {
  public void run() throws Exception {
    var language =
        DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:32:default"));
    var program =
        new ProgramDB(getScriptArgs()[0], language, language.getDefaultCompilerSpec(), this);
    try {
      int tx = program.startTransaction("unsupported string charset fixture");
      try {
        var space = program.getAddressFactory().getDefaultAddressSpace();
        String[] values = {"unknown", "illegal", "live", "??..."};
        String[] charsets = {"not-an-installed-charset", "bad charset", "US-ASCII", "US-ASCII"};
        for (int i = 0; i < values.length; i++) {
          byte[] bytes = (values[i] + "\0").getBytes(StandardCharsets.US_ASCII);
          var address = space.getAddress(0x1000 + i * 0x100);
          program
              .getMemory()
              .createInitializedBlock(
                  "string" + i,
                  address,
                  new ByteArrayInputStream(bytes),
                  bytes.length,
                  monitor,
                  false);
          var data =
              program.getListing().createData(address, StringDataType.dataType, bytes.length);
          CharsetSettingsDefinition.CHARSET.setCharset(data, charsets[i]);
          program
              .getReferenceManager()
              .addMemoryReference(address, address, RefType.DATA, SourceType.USER_DEFINED, 0);
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
