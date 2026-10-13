import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.*;

public class CreateNamespaceOwnerFixture extends GhidraScript {
  public void run() throws Exception {
    var table = currentProgram.getSymbolTable();
    var global = currentProgram.getGlobalNamespace();
    var owner =
        getScriptArgs()[0].equals("class")
            ? table.createClass(global, getScriptArgs()[1], SourceType.USER_DEFINED)
            : table.createNameSpace(global, getScriptArgs()[1], SourceType.USER_DEFINED);
    table.createLabel(toAddr("1010"), getScriptArgs()[1], owner, SourceType.USER_DEFINED);
    table.createLabel(toAddr("1020"), getScriptArgs()[1], global, SourceType.USER_DEFINED);
    currentProgram
        .getFunctionManager()
        .createFunction(
            "owned_function",
            owner,
            toAddr("1030"),
            new AddressSet(toAddr("1030"), toAddr("103f")),
            SourceType.USER_DEFINED);
  }
}
