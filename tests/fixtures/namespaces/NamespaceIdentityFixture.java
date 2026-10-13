import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.SourceType;

public class NamespaceIdentityFixture extends GhidraScript {
  public void run() throws Exception {
    var table = currentProgram.getSymbolTable();
    var global = currentProgram.getGlobalNamespace();
    if (getScriptArgs().length == 0) {
      var flat = table.createNameSpace(global, "identity::parent", SourceType.USER_DEFINED);
      var root = table.createNameSpace(global, "identity", SourceType.USER_DEFINED);
      table.createNameSpace(root, "parent", SourceType.USER_DEFINED);
      table.createNameSpace(flat, "child", SourceType.USER_DEFINED);
      table.createLabel(toAddr(0x1070), "identity_symbol", flat, SourceType.USER_DEFINED);
      table.createLabel(toAddr(0x1080), "identity_symbol", global, SourceType.USER_DEFINED);
      return;
    }
    var flat = table.getNamespace("identity::parent", global);
    var root = table.getNamespace("identity", global);
    var nested = table.getNamespace("parent", root);
    table.getSymbols("identity_symbol", flat).get(0).setNamespace(nested);
    table.getNamespace("child", flat).getSymbol().setNamespace(nested);
  }
}
