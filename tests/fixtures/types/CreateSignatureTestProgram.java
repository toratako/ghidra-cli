import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;

public class CreateSignatureTestProgram extends GhidraScript {
  public void run() throws Exception {
    var language =
        DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
    var program =
        new ProgramDB(getScriptArgs()[0], language, language.getDefaultCompilerSpec(), this);
    try {
      int tx = program.startTransaction("signature fixture");
      try {
        var address = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
        program.getMemory().createInitializedBlock("code", address, 16, (byte) 0, monitor, false);
        var function =
            program
                .getFunctionManager()
                .createFunction(
                    "signature_target",
                    address,
                    new AddressSet(address, address.add(15)),
                    SourceType.USER_DEFINED);
        program
            .getSymbolTable()
            .createLabel(address.add(1), "collision", function, SourceType.USER_DEFINED);
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
