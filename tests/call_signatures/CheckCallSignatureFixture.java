import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.pcode.DataTypeSymbol;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.symbol.SymbolType;

public class CheckCallSignatureFixture extends GhidraScript {
    private DataTypeSymbol override(int offset) {
        var caller = getFunctionAt(toAddr(0x1000));
        var namespace = HighFunction.findOverrideSpace(caller);
        for (var symbol : currentProgram.getSymbolTable().getSymbols(toAddr(offset))) {
            if (symbol.getSymbolType() == SymbolType.LABEL && symbol.getName().startsWith("prt_")
                    && symbol.getParentNamespace().equals(namespace)) {
                return HighFunctionDBUtil.readOverride(symbol);
            }
        }
        return null;
    }

    public void run() throws Exception {
        switch (getScriptArgs()[0]) {
            case "shared": {
                var first = override(0x1005);
                var second = override(0x1012);
                if (first == null || second == null || !first.getDataType().equals(second.getDataType())) {
                    throw new IllegalStateException("Sites must share the same saved override datatype");
                }
                break;
            }
            case "clean": {
                var category = currentProgram.getDataTypeManager().getCategory(new CategoryPath(HighFunctionDBUtil.AUTO_CAT));
                if (category != null) {
                    for (var type : category.getDataTypes()) {
                        if (type instanceof ghidra.program.model.data.FunctionDefinition) {
                            throw new IllegalStateException("Unused override datatype remains: " + type.getPathName());
                        }
                    }
                }
                break;
            }
            default: throw new IllegalArgumentException("Unknown fixture check");
        }
    }
}
