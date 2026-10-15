import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;

public class CreateRecursiveCodeFixture extends GhidraScript {
  public void run() throws Exception {
    if (getScriptArgs().length == 1 && getScriptArgs()[0].equals("remove-cycle")) {
      var memory = currentProgram.getMemory();
      memory.removeBlock(memory.getBlock(toAddr(0x1001)), monitor);
      return;
    }
    if (getScriptArgs().length == 0) {
      // Add the cycle after program selection: native analyzer option probes
      // also read this opcode and reject the program while opening it.
      currentProgram
          .getMemory()
          .createByteMappedBlock("cycle", toAddr(0x1001), toAddr(0x1001), 16, false)
          .setExecute(true);
      return;
    }
    var language =
        DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:32:default"));
    var program =
        new ProgramDB(getScriptArgs()[0], language, language.getDefaultCompilerSpec(), this);
    try {
      int tx = program.startTransaction("recursive code fixture");
      try {
        var space = program.getAddressFactory().getDefaultAddressSpace();
        var memory = program.getMemory();
        // MOV's immediate reads the cyclic mapping after its initialized opcode.
        memory
            .createInitializedBlock(
                "opcode", space.getAddress(0x1000), 1, (byte) 0xb8, monitor, false)
            .setExecute(true);
        var retained = space.getAddress(0x2000);
        memory
            .createInitializedBlock("retained", retained, 1, (byte) 0xc3, monitor, false)
            .setExecute(true);
        var command = new DisassembleCommand(retained, null, false);
        command.enableCodeAnalysis(false);
        if (!command.applyTo(program, monitor)) {
          throw new IllegalStateException("Could not define retained instruction");
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
