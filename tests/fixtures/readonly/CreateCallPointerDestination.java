import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;

public class CreateCallPointerDestination extends GhidraScript {
  public void run() throws Exception {
    var language =
        DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
    var program =
        new ProgramDB(getScriptArgs()[0], language, language.getDefaultCompilerSpec(), this);
    try {
      int tx = program.startTransaction("call pointer destination");
      try {
        var space = program.getAddressFactory().getDefaultAddressSpace();
        var source = SourceType.USER_DEFINED;
        program
            .getMemory()
            .createInitializedBlock(
                "code", space.getAddress(0x1000), 0x3000, (byte) 0, monitor, false);
        String[] names = {"direct", "indirect", "overridden", "pointee"};
        long[] entries = {0x1000, 0x1100, 0x1200, 0x3000};
        byte[][] code = {
          {(byte) 0xe8, (byte) 0xfb, 0x0f, 0, 0, (byte) 0xc3},
          {(byte) 0xff, 0x15, (byte) 0xfa, 0x0e, 0, 0, (byte) 0xc3},
          {(byte) 0xff, (byte) 0xd0, (byte) 0xc3},
          {(byte) 0xc3}
        };
        for (int i = 0; i < names.length; i++) {
          var entry = space.getAddress(entries[i]);
          var body = new AddressSet(entry, entry.add(code[i].length - 1));
          program.getMemory().setBytes(entry, code[i]);
          if (!new DisassembleCommand(entry, body, false).applyTo(program, monitor))
            throw new IllegalStateException("Cannot disassemble " + names[i]);
          program.getFunctionManager().createFunction(names[i], entry, body, source);
        }
        var slot = space.getAddress(0x2000);
        program.getMemory().setBytes(slot, new byte[] {0, 0x30, 0, 0, 0, 0, 0, 0});
        program.getListing().createData(slot, PointerDataType.dataType);
        var refs = program.getReferenceManager();
        refs.addMemoryReference(slot, space.getAddress(0x3000), RefType.DATA, source, 0);
        var override =
            refs.addMemoryReference(
                space.getAddress(0x1200), slot, RefType.CALL_OVERRIDE_UNCONDITIONAL, source, 0);
        refs.setPrimary(override, true);
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
