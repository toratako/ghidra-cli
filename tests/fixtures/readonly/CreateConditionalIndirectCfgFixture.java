import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;

public class CreateConditionalIndirectCfgFixture extends GhidraScript {
  private Address address(Program program, long offset) {
    return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
  }

  private void function(Program program, String name, long offset, int first) throws Exception {
    Address entry = address(program, offset);
    AddressSet body = new AddressSet(entry, entry.add(7));
    program.getMemory().setInt(entry, first);
    program.getMemory().setInt(entry.add(4), 0xe12fff1e); // bx lr
    if (!new DisassembleCommand(entry, body, true).applyTo(program, monitor)) {
      throw new IllegalStateException("Could not disassemble " + name);
    }
    program.getFunctionManager().createFunction(name, entry, body, SourceType.USER_DEFINED);
  }

  public void run() throws Exception {
    var language =
        DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("ARM:LE:32:v8"));
    var program =
        new ProgramDB(getScriptArgs()[0], language, language.getDefaultCompilerSpec(), this);
    try {
      int transaction = program.startTransaction("conditional indirect CFG fixture");
      try {
        var code =
            program
                .getMemory()
                .createInitializedBlock(
                    "code", address(program, 0x1000), 0x200, (byte) 0, monitor, false);
        code.setExecute(true);
        function(program, "conditional_indirect", 0x1000, 0x112fff10); // bxne r0
        function(program, "conditional_direct_next", 0x1100, 0x1affffff); // bne 0x1104
      } finally {
        program.endTransaction(transaction, true);
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
