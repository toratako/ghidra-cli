import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;

public class CreateDynamicSymbol extends GhidraScript {
  public void run() throws Exception {
    currentProgram
        .getReferenceManager()
        .addMemoryReference(
            toAddr("1000"), toAddr("1010"), RefType.DATA, SourceType.USER_DEFINED, 0);
    if (!currentProgram.getSymbolTable().getPrimarySymbol(toAddr("1010")).isDynamic())
      throw new IllegalStateException("fixture must have a dynamic label");
  }
}
