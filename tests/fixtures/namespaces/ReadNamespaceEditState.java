import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;

public class ReadNamespaceEditState extends GhidraScript {
    public void run() throws Exception {
        var result = new JsonObject();
        var symbols = new JsonArray();
        var iterator = currentProgram.getSymbolTable().getDefinedSymbols();
        while (iterator.hasNext()) {
            var symbol = iterator.next();
            if (symbol.isDynamic()) continue;
            var row = new JsonObject();
            row.addProperty("id", Long.toString(symbol.getID()));
            row.addProperty("name", symbol.getName());
            row.addProperty("path", symbol.getName(true));
            row.addProperty("type", symbol.getSymbolType().toString());
            symbols.add(row);
        }
        result.add("symbols", symbols);
        var functions = new JsonArray();
        var functionIterator = currentProgram.getFunctionManager().getFunctions(true);
        while (functionIterator.hasNext()) {
            var function = functionIterator.next();
            var row = new JsonObject();
            row.addProperty("id", Long.toString(function.getID()));
            row.addProperty("path", function.getName(true));
            row.addProperty("signature", function.getSignature().toString());
            functions.add(row);
        }
        result.add("functions", functions);
        byte[] bytes = new byte[0x100];
        currentProgram.getMemory().getBytes(toAddr(0x1000), bytes);
        result.addProperty("bytes", java.util.HexFormat.of().formatHex(bytes));
        println(result.toString());
    }
}
