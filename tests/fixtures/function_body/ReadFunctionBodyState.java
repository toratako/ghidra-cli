import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.SymbolType;

public class ReadFunctionBodyState extends GhidraScript {
    public void run() throws Exception {
        var base = currentProgram.getMemory().getBlock("code").getStart();
        var function = currentProgram.getFunctionManager().getFunctionAt(base);
        JsonObject result = new JsonObject();
        JsonArray ranges = new JsonArray();
        for (var range : function.getBody().getAddressRanges()) {
            JsonObject row = new JsonObject();
            row.addProperty("start", range.getMinAddress().getOffset());
            row.addProperty("end", range.getMaxAddress().getOffset());
            ranges.add(row);
        }
        result.add("body", ranges);
        JsonArray labels = new JsonArray();
        var symbols = currentProgram.getSymbolTable().getAllSymbols(true);
        while (symbols.hasNext()) {
            var symbol = symbols.next();
            if (symbol.getSymbolType() != SymbolType.LABEL) continue;
            JsonObject row = new JsonObject();
            row.addProperty("name", symbol.getName(true));
            row.addProperty("address", symbol.getAddress().getOffset());
            labels.add(row);
        }
        result.add("labels", labels);
        JsonArray references = new JsonArray();
        for (var reference : currentProgram.getReferenceManager().getReferencesFrom(base.add(0x15))) {
            JsonObject row = new JsonObject();
            row.addProperty("to_space", reference.getToAddress().getAddressSpace().getName());
            row.addProperty("to_offset", reference.getToAddress().getOffset());
            row.addProperty("operand", reference.getOperandIndex());
            row.addProperty("symbol", reference.getSymbolID());
            references.add(row);
        }
        result.add("references", references);
        result.addProperty("instruction_count", currentProgram.getListing().getNumInstructions());
        result.addProperty("extension_defined",
            currentProgram.getListing().getInstructionAt(base.add(0x20)) != null);
        println("body-state=" + result);
    }
}
