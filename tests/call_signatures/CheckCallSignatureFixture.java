import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.pcode.DataTypeSymbol;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.symbol.SymbolType;

public class CheckCallSignatureFixture extends GhidraScript {
    private void require(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }

    private DataType pointee(DataType type) {
        require(type instanceof Pointer, "Expected a pointer, got " + type);
        require(type.getLength() == currentProgram.getDefaultPointerSize(), "Incorrect pointer width: " + type);
        return ((Pointer) type).getDataType();
    }

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
            case "inventory": {
                var manager = currentProgram.getDataTypeManager();
                var result = new JsonObject();
                var types = manager.getAllDataTypes();
                while (types.hasNext()) {
                    var type = types.next();
                    var row = new JsonObject();
                    row.addProperty("id", manager.getID(type));
                    row.addProperty("universal_id", String.valueOf(type.getUniversalID()));
                    row.addProperty("definition", type.toString());
                    result.add(type.getPathName(), row);
                }
                println(result.toString());
                break;
            }
            case "callbacks": {
                var manager = currentProgram.getDataTypeManager();
                var profile = manager.getDataType("/Recovered/Profile");
                var alias = manager.getDataType("/Recovered/ProfileCmp");
                var originalCallback = manager.getDataType("/Callbacks/ProfileCmp");
                require(alias instanceof TypeDef, "The original pointer typedef was lost");
                require(pointee(((TypeDef) alias).getDataType()).equals(originalCallback),
                    "The original typedef target changed");
                var saved = override(0x1005);
                require(saved != null, "The selected call-site override is missing");
                require(override(0x1012) == null, "The unselected call site was changed");
                var args = ((FunctionDefinition) saved.getDataType()).getArguments();
                require(args.length == 2 && args[0].getDataType().equals(alias),
                    "The bound argument does not use the original typedef identity");
                var visitType = pointee(args[1].getDataType());
                require(visitType instanceof FunctionDefinition, "The inline callback is not a function pointer");
                var visit = (FunctionDefinition) visitType;
                require(visit.getArguments().length == 2, "The inline callback arguments were lost");
                require(pointee(visit.getArguments()[0].getDataType()).equals(profile),
                    "The inline callback lost the original Profile identity");
                var finishType = pointee(visit.getArguments()[1].getDataType());
                require(finishType instanceof FunctionDefinition, "The nested callback is not a function pointer");
                var finish = (FunctionDefinition) finishType;
                require(finish.getArguments().length == 2, "The nested callback arguments were lost");
                require(pointee(finish.getArguments()[0].getDataType()).equals(profile),
                    "The nested callback lost the original Profile identity");
                require("int".equals(finish.getArguments()[1].getDataType().getName()),
                    "The nested callback scalar argument changed");
                var types = manager.getAllDataTypes();
                while (types.hasNext()) {
                    var type = types.next();
                    require(!(type instanceof TypeDef) || type.equals(alias),
                        "Parsing introduced a temporary typedef: " + type.getPathName());
                }
                break;
            }
            default: throw new IllegalArgumentException("Unknown fixture check");
        }
    }
}
