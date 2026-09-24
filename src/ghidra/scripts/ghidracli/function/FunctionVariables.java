package ghidracli.function;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.EquateSymbol;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.UnionFacetSymbol;
import ghidracli.query.AddressCodec;
import ghidracli.session.ProgramSession;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static ghidracli.protocol.JsonProtocol.errorResult;
import static ghidracli.protocol.JsonProtocol.getArgString;
import static ghidracli.protocol.JsonProtocol.getDecompileTimeoutArg;

/** Fresh decompiler variables and guarded selection shared by reads, edits and inference. */
public final class FunctionVariables {
    private final ProgramSession session;
    private final FunctionQueries functionQueries;

    public FunctionVariables(ProgramSession session, FunctionQueries functionQueries) {
        this.session = session;
        this.functionQueries = functionQueries;
    }

    public record Decompilation(DecompileResults results, HighFunction high, List<HighSymbol> symbols) {}

    public Function function(JsonObject args) throws Exception {
        if (session.program() == null) throw new IllegalArgumentException("No program loaded");
        String target = getArgString(args, "target");
        if (target == null || target.isBlank()) throw new IllegalArgumentException("Function target required");
        Function function = functionQueries.findFunctionByNameOrAddress(target);
        if (function == null) throw new IllegalArgumentException(functionQueries.buildFunctionTargetHint(target));
        return function;
    }

    public static String variableName(JsonObject args) {
        String name = getArgString(args, "var_name");
        if (name == null || name.isBlank()) throw new IllegalArgumentException("Variable name required (--var)");
        return name;
    }

    public Decompilation decompile(Function function, JsonObject args) throws Exception {
        DecompileResults results = session.decompile(function, getDecompileTimeoutArg(args));
        if (!results.decompileCompleted()) {
            String reason = results.isTimedOut() ? "Decompilation timed out" : "Decompilation failed";
            throw new IllegalStateException(reason + " for " + function.getName() + ": " + results.getErrorMessage());
        }
        HighFunction high = results.getHighFunction();
        if (high == null) throw new IllegalStateException("Could not get high-level function representation");
        List<HighSymbol> symbols = new ArrayList<>();
        var iterator = high.getLocalSymbolMap().getSymbols();
        while (iterator.hasNext()) {
            session.monitor().checkCancelled();
            HighSymbol symbol = iterator.next();
            if (isVariable(symbol)) symbols.add(symbol);
        }
        session.monitor().checkCancelled();
        return new Decompilation(results, high, symbols);
    }

    public static boolean isVariable(HighSymbol symbol) {
        // Constants and union-field annotations share the local symbol map
        // but do not represent local/parameter variables.
        return !symbol.isGlobal() && !(symbol instanceof EquateSymbol)
            && !(symbol instanceof UnionFacetSymbol);
    }

    public Selection select(Function function, List<HighSymbol> symbols, String name, JsonObject args) {
        JsonObject expected = null;
        if (args.has("selection")) {
            JsonElement value = args.get("selection");
            if (!value.isJsonObject()) return Selection.error(errorResult("selection must be a variable snapshot"));
            JsonObject selection = value.getAsJsonObject();
            if (!selection.keySet().equals(Set.of("project", "program", "function_address", "modification", "variable"))
                    || !selection.get("project").isJsonObject()
                    || !isString(selection.get("program")) || !isString(selection.get("function_address"))
                    || !isString(selection.get("modification")) || !selection.get("variable").isJsonObject()) {
                return Selection.error(errorResult("selection must contain project, program, function_address, modification and a complete variable row"));
            }
            if (!project().equals(selection.getAsJsonObject("project"))
                    || !session.programPath().equals(selection.get("program").getAsString())
                    || !AddressCodec.format(function.getEntryPoint()).equals(selection.get("function_address").getAsString())
                    || !modification().equals(selection.get("modification").getAsString())) {
                return stale();
            }
            expected = selection.getAsJsonObject("variable");
        }

        JsonArray candidates = new JsonArray();
        HighSymbol match = null;
        for (HighSymbol symbol : symbols) {
            if (!symbol.getName().equals(name)) continue;
            JsonObject row = describe(symbol);
            if (expected != null && !expected.equals(row)) continue;
            candidates.add(row);
            match = symbol;
        }
        if (candidates.size() == 1) return new Selection(match, null);
        if (expected != null) return stale();
        if (candidates.isEmpty()) {
            return Selection.error(errorResult("Variable not found: " + name + " in function " + function.getName()));
        }
        JsonObject error = errorResult("Ambiguous variable name: " + name);
        JsonObject detail = new JsonObject();
        detail.add("candidates", candidates);
        error.add("detail", detail);
        return Selection.error(error);
    }

    private static Selection stale() {
        return Selection.error(errorResult("Variable selection is stale or no longer unique; list variables again"));
    }

    private static boolean isString(JsonElement value) {
        return value != null && value.isJsonPrimitive() && value.getAsJsonPrimitive().isString();
    }

    public String modification() {
        return Long.toString(session.program().getModificationNumber());
    }

    public JsonObject project() {
        var locator = session.state().getProject().getProjectLocator();
        JsonObject result = new JsonObject();
        result.addProperty("location", locator.getLocation());
        result.addProperty("name", locator.getName());
        return result;
    }

    public static JsonObject context(Function function) {
        JsonObject result = new JsonObject();
        result.addProperty("function", function.getName());
        result.addProperty("address", AddressCodec.format(function.getEntryPoint()));
        return result;
    }

    public static JsonObject describe(HighSymbol symbol) {
        JsonObject result = describeType(symbol.getName(), symbol.getDataType(), symbol.getSize(),
            symbol.getStorage().toString());
        result.addProperty("kind", symbol.isParameter() ? "parameter" : "local");
        if (symbol.isParameter()) {
            result.addProperty("ordinal", symbol.getCategoryIndex());
        } else {
            result.addProperty("first_use", symbol.getPCAddress() == null ? null : AddressCodec.format(symbol.getPCAddress()));
        }
        return result;
    }

    static JsonObject describeType(String name, DataType type, int size, String storage) {
        JsonObject result = new JsonObject();
        result.addProperty("name", name);
        result.addProperty("type", type.getName());
        result.addProperty("type_path", type.getPathName());
        result.addProperty("size", size);
        result.addProperty("storage", storage);
        return result;
    }

    public record Selection(HighSymbol symbol, JsonObject error) {
        static Selection error(JsonObject error) { return new Selection(null, error); }
    }
}
