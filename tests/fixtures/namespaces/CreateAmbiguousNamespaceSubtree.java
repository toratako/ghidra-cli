
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.SourceType;
public class CreateAmbiguousNamespaceSubtree extends GhidraScript {
    public void run() throws Exception {
        var table = currentProgram.getSymbolTable();
        var root = table.createNameSpace(currentProgram.getGlobalNamespace(), "tree", SourceType.USER_DEFINED);
        table.createNameSpace(root, "x::y", SourceType.USER_DEFINED);
        var x = table.createNameSpace(root, "x", SourceType.USER_DEFINED);
        table.createNameSpace(x, "y", SourceType.USER_DEFINED);
    }
}
