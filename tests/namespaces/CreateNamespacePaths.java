import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.SourceType;

public class CreateNamespacePaths extends GhidraScript {
    public void run() throws Exception {
        var table = currentProgram.getSymbolTable();
        var global = currentProgram.getGlobalNamespace();
        var std = table.createNameSpace(global, "std", SourceType.USER_DEFINED);
        table.createClass(std, "vector<ns::Item>", SourceType.USER_DEFINED);
        // Native names can contain the same delimiter used to display ancestry.
        var flat = table.createNameSpace(global, "a::b", SourceType.USER_DEFINED);
        var ancestor = table.createNameSpace(global, "a", SourceType.USER_DEFINED);
        var nested = table.createNameSpace(ancestor, "b", SourceType.USER_DEFINED);
        table.createLabel(toAddr(0x1070), "flat_marker", flat, SourceType.USER_DEFINED);
        table.createLabel(toAddr(0x1080), "nested_marker", nested, SourceType.USER_DEFINED);
    }
}
