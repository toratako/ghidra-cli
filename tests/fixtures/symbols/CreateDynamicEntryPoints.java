import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;

public class CreateDynamicEntryPoints extends GhidraScript {
  public void run() throws Exception {
    var table = currentProgram.getSymbolTable();
    table.addExternalEntryPoint(toAddr(0x1010));
    table.createLabel(toAddr(0x1020), "named_entry", SourceType.USER_DEFINED);
    table.addExternalEntryPoint(toAddr(0x1020));
    currentProgram
        .getReferenceManager()
        .addMemoryReference(
            toAddr(0x1000), toAddr(0x1030), RefType.DATA, SourceType.USER_DEFINED, 0);
    if (!table.getPrimarySymbol(toAddr(0x1010)).isDynamic()
        || !table.getPrimarySymbol(toAddr(0x1030)).isDynamic()) {
      throw new IllegalStateException("Expected generated entry and non-entry labels");
    }
  }
}
