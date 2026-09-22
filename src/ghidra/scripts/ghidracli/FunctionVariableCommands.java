package ghidracli;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.EquateSymbol;
import ghidra.program.model.pcode.UnionFacetSymbol;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolUtilities;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import static ghidracli.JsonProtocol.errorResult;
import static ghidracli.JsonProtocol.getArgString;
import static ghidracli.JsonProtocol.getDecompileTimeoutArg;

/** Decompiler variable discovery and edits to their corresponding database definitions. */
final class FunctionVariableCommands {
    private final ProgramSession session;
    private final FunctionQueries functionQueries;
    private final TypeResolver typeResolver;

    FunctionVariableCommands(ProgramSession session, FunctionQueries functionQueries,
            TypeResolver typeResolver) {
        this.session = session;
        this.functionQueries = functionQueries;
        this.typeResolver = typeResolver;
    }

    JsonObject handleFunctionVarList(JsonObject args) {
        try {
            Function function = function(args);
            List<HighSymbol> symbols = decompile(function, args);
            JsonArray rows = new JsonArray();
            for (HighSymbol symbol : symbols) rows.add(describe(symbol));
            JsonObject result = context(function);
            result.addProperty("program", session.programPath());
            result.addProperty("modification", modification());
            result.add("variables", rows);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to list variables: " + e.getMessage(), e);
        }
    }

    JsonObject handleFunctionVarGet(JsonObject args) {
        try {
            Function function = function(args);
            String name = variableName(args);
            List<HighSymbol> symbols = decompile(function, args);
            Selection selected = select(function, symbols, name, args);
            if (selected.error != null) return selected.error;
            JsonObject result = context(function);
            result.add("decompiler", describe(selected.symbol));
            result.add("database", describeDatabase(function, savedVariable(function, selected.symbol)));
            return result;
        } catch (Exception e) {
            return errorResult("Failed to get variable: " + e.getMessage(), e);
        }
    }

    JsonObject handleFunctionVarSet(JsonObject args) {
        try {
            Function function = function(args);
            String name = variableName(args);
            String newName = getArgString(args, "new_name");
            String typeName = getArgString(args, "type_name");
            if (newName == null && typeName == null) {
                return errorResult("At least one of --name or --type is required");
            }
            if (newName != null) SymbolUtilities.validateName(newName);
            DataType newType = null;
            if (typeName != null) {
                if (typeName.isBlank()) return errorResult("Type name must not be empty (--type)");
                newType = typeResolver.resolveDataType(typeName);
                if (newType == null) return errorResult("Type not found: " + typeName);
                newType = newType.clone(session.program().getDataTypeManager());
                if (newType.getLength() <= 0) {
                    return errorResult("Type must have a fixed positive size: " + typeName);
                }
            }

            List<HighSymbol> symbols = decompile(function, args);
            Selection selected = select(function, symbols, name, args);
            if (selected.error != null) return selected.error;
            HighSymbol target = selected.symbol;
            String effectiveName = newName != null ? newName : target.getName();
            Variable saved = savedVariable(function, target);
            if (saved instanceof Parameter parameter && parameter.isAutoParameter()) {
                return errorResult("Cannot modify auto-parameter: " + parameter.getName());
            }
            Symbol existingSymbol = saved == null ? null : saved.getSymbol();
            // Ghidra applies the type before renaming. Reject known conflicts
            // before its helper can touch a variable or commit inferred inputs.
            for (HighSymbol other : symbols) {
                if (other != target && other.getName().equals(effectiveName)) {
                    return errorResult("Variable name conflicts with another symbol: " + effectiveName);
                }
            }
            for (Symbol symbol : session.program().getSymbolTable().getSymbols(effectiveName, function)) {
                if (!symbol.equals(existingSymbol)) {
                    return errorResult("Variable name conflicts with another symbol: " + effectiveName);
                }
            }

            JsonObject decompiler = describe(target);
            JsonElement before = describeDatabase(function, saved);
            // Null preserves the saved type during a rename; inferred locals
            // receive sized undefined types through Ghidra's normal helper.
            // The helper also rejects convention-generated auto parameters.
            HighFunctionDBUtil.updateDBVariable(target, newName, newType, SourceType.USER_DEFINED);

            Variable updated = target.isParameter() ? function.getParameter(target.getCategoryIndex()) : null;
            if (!target.isParameter()) {
                for (Variable variable : function.getLocalVariables()) {
                    if (variable.getName().equals(effectiveName)) {
                        if (updated != null) throw new IllegalStateException("Edited variable is ambiguous in the database");
                        updated = variable;
                    }
                }
            }
            if (updated == null) throw new IllegalStateException("Edited variable could not be read from the database");

            JsonObject result = context(function);
            result.addProperty("status", "updated");
            result.addProperty("kind", target.isParameter() ? "parameter" : "local");
            result.add("decompiler", decompiler);
            result.add("before", before);
            result.add("after", describeDatabase(function, updated));
            return result;
        } catch (Exception e) {
            return errorResult("Failed to set variable: " + e.getMessage(), e);
        }
    }

    private Function function(JsonObject args) throws Exception {
        if (session.program() == null) throw new IllegalArgumentException("No program loaded");
        String target = getArgString(args, "target");
        if (target == null || target.isBlank()) throw new IllegalArgumentException("Function target required");
        Function function = functionQueries.findFunctionByNameOrAddress(target);
        if (function == null) throw new IllegalArgumentException(functionQueries.buildFunctionTargetHint(target));
        return function;
    }

    private static String variableName(JsonObject args) {
        String name = getArgString(args, "var_name");
        if (name == null || name.isBlank()) throw new IllegalArgumentException("Variable name required (--var)");
        return name;
    }

    private List<HighSymbol> decompile(Function function, JsonObject args) throws Exception {
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
            // Constants and union-field annotations share the local symbol map
            // but do not represent editable local/parameter variables.
            if (!symbol.isGlobal() && !(symbol instanceof EquateSymbol)
                    && !(symbol instanceof UnionFacetSymbol)) symbols.add(symbol);
        }
        return symbols;
    }

    private Selection select(Function function, List<HighSymbol> symbols, String name, JsonObject args) {
        JsonObject expected = null;
        if (args.has("selection")) {
            JsonElement value = args.get("selection");
            if (!value.isJsonObject()) return Selection.error(errorResult("selection must be a variable snapshot"));
            JsonObject selection = value.getAsJsonObject();
            if (!selection.keySet().equals(Set.of("program", "function_address", "modification", "variable"))
                    || !isString(selection.get("program")) || !isString(selection.get("function_address"))
                    || !isString(selection.get("modification")) || !selection.get("variable").isJsonObject()) {
                return Selection.error(errorResult("selection must contain program, function_address, modification and a complete variable row"));
            }
            if (!session.programPath().equals(selection.get("program").getAsString())
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

    private String modification() {
        return Long.toString(session.program().getModificationNumber());
    }

    private static JsonObject context(Function function) {
        JsonObject result = new JsonObject();
        result.addProperty("function", function.getName());
        result.addProperty("address", AddressCodec.format(function.getEntryPoint()));
        return result;
    }

    private static JsonObject describe(HighSymbol symbol) {
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

    private static Variable savedVariable(Function function, HighSymbol high) {
        Symbol symbol = high.getSymbol();
        if (symbol != null && symbol.getObject() instanceof Variable variable) return variable;
        if (high.isParameter()) {
            Parameter parameter = function.getParameter(high.getCategoryIndex());
            return parameter != null && parameter.getVariableStorage().compareTo(high.getStorage()) == 0
                ? parameter : null;
        }
        return HighFunctionDBUtil.getFunctionVariable(high);
    }

    private static JsonElement describeDatabase(Function function, Variable variable) {
        if (variable == null) return JsonNull.INSTANCE;
        JsonObject result = describeType(variable.getName(), variable.getDataType(), variable.getLength(),
            variable.getVariableStorage().toString());
        result.addProperty("source", variable.getSource().name());
        if (variable instanceof Parameter parameter) {
            result.addProperty("kind", "parameter");
            result.addProperty("ordinal", parameter.getOrdinal());
            result.addProperty("auto_parameter", parameter.getAutoParameterType() == null
                ? null : parameter.getAutoParameterType().name());
        } else {
            result.addProperty("kind", "local");
            result.addProperty("first_use", AddressCodec.format(function.getEntryPoint().addWrap(variable.getFirstUseOffset())));
        }
        return result;
    }

    private static JsonObject describeType(String name, DataType type, int size, String storage) {
        JsonObject result = new JsonObject();
        result.addProperty("name", name);
        result.addProperty("type", type.getName());
        result.addProperty("type_path", type.getPathName());
        result.addProperty("size", size);
        result.addProperty("storage", storage);
        return result;
    }

    private record Selection(HighSymbol symbol, JsonObject error) {
        static Selection error(JsonObject error) { return new Selection(null, error); }
    }
}
