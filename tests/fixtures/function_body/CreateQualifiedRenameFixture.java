import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.SourceType;

public class CreateQualifiedRenameFixture extends GhidraScript {
  public void run() throws Exception {
    var symbols = currentProgram.getSymbolTable();
    var functions = currentProgram.getFunctionManager();
    var left = symbols.createNameSpace(null, "left", SourceType.USER_DEFINED);
    var right = symbols.createNameSpace(null, "right", SourceType.USER_DEFINED);
    functions
        .getFunctionAt(
            currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000))
        .setParentNamespace(left);
    var other =
        functions.getFunctionAt(
            currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(0x1100));
    other.setParentNamespace(right);
    other.setName("subject", SourceType.USER_DEFINED);
  }
}
