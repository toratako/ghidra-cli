import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;

public class CreateGraphDepthFixture extends GhidraScript {
  public void run() throws Exception {
    var language =
        DefaultLanguageService.getLanguageService()
            .getLanguage(new LanguageID("x86:LE:64:default"));
    var program =
        new ProgramDB(getScriptArgs()[0], language, language.getDefaultCompilerSpec(), this);
    try {
      int tx = program.startTransaction("graph depth fixture");
      try {
        String[] names = {"root", "long1", "long2", "short", "join", "tail", "leaf"};
        int[][] edges = {{0, 1}, {0, 3}, {1, 2}, {2, 4}, {3, 4}, {4, 5}, {5, 6}, {6, 4}};
        for (int direction = 0; direction < 2; direction++) {
          String prefix = direction == 0 ? "callees_" : "callers_";
          Address base =
              program
                  .getAddressFactory()
                  .getDefaultAddressSpace()
                  .getAddress(0x1000 + direction * 0x1000);
          program
              .getMemory()
              .createInitializedBlock(prefix + "code", base, 0x100, (byte) 0, monitor, false);
          for (int i = 0; i < names.length; i++) {
            Address entry = base.add(i * 0x10);
            program
                .getFunctionManager()
                .createFunction(
                    prefix + names[i],
                    entry,
                    new AddressSet(entry, entry.add(0xf)),
                    SourceType.USER_DEFINED);
          }
          int[] sites = new int[names.length];
          for (int[] edge : edges) {
            int from = edge[direction];
            int to = edge[1 - direction];
            Address site = base.add(from * 0x10 + 2 * sites[from]++);
            program.getMemory().setBytes(site, new byte[] {(byte) 0xff, (byte) 0xd0});
            if (!new DisassembleCommand(site, new AddressSet(site, site.add(1)), false)
                .applyTo(program, monitor)) {
              throw new IllegalStateException("Could not disassemble call at " + site);
            }
            program
                .getReferenceManager()
                .addMemoryReference(
                    site,
                    base.add(to * 0x10),
                    RefType.UNCONDITIONAL_CALL,
                    SourceType.USER_DEFINED,
                    0);
          }
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
