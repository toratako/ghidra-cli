import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;

public class CreateOrderedParametersFixture extends GhidraScript {
  public void run() throws Exception {
    var language =
        DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:32:default"));
    var program =
        new ProgramDB(getScriptArgs()[0], language, language.getDefaultCompilerSpec(), this);
    try {
      int tx = program.startTransaction("ordered parameter fixture");
      try {
        var address = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
        program.getMemory().createInitializedBlock("code", address, 1, (byte) 0xc3, monitor, false);
        if (!new DisassembleCommand(address, null, false).applyTo(program, monitor)) {
          throw new IllegalStateException("Fixture disassembly failed");
        }
        var function =
            program
                .getFunctionManager()
                .createFunction(
                    "ordered_params",
                    address,
                    new AddressSet(address, address),
                    SourceType.USER_DEFINED);
        function.setCallingConvention("__cdecl");
        function.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED);
        // Symbol allocation order deliberately differs from the final parameter order.
        for (String name : new String[] {"p1", "p2", "p3", "p4", "p0"}) {
          function.addParameter(
              new ParameterImpl(name, IntegerDataType.dataType, program), SourceType.USER_DEFINED);
        }
        function.moveParameter(4, 0);
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
