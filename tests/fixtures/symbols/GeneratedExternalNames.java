import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;

public class GeneratedExternalNames extends GhidraScript {
  public void run() throws Exception {
    var external = currentProgram.getExternalManager();
    var function =
        external.addExtFunction("generated_library", null, toAddr(0x2000), SourceType.DEFAULT);
    var label =
        external.addExtLocation("generated_library", null, toAddr(0x3000), SourceType.DEFAULT);
    var references = currentProgram.getReferenceManager();
    references.addExternalReference(
        toAddr(0x1000), 0, function, SourceType.USER_DEFINED, RefType.UNCONDITIONAL_CALL);
    references.addExternalReference(
        toAddr(0x1001), 0, label, SourceType.USER_DEFINED, RefType.DATA);
    currentProgram
        .getSymbolTable()
        .createLabel(toAddr(0x1040), function.getSymbol().getName(), SourceType.USER_DEFINED);
  }
}
