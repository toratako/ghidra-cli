package ghidracli.function;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.AutoParameterType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidracli.query.AddressCodec;
import ghidracli.session.ProgramSession;
import ghidracli.types.TypeResolver;
import java.util.List;
import java.util.Locale;

import static ghidracli.protocol.JsonProtocol.errorResult;
import static ghidracli.protocol.JsonProtocol.getArgString;
import static ghidracli.function.FunctionVariables.context;
import static ghidracli.function.FunctionVariables.describe;
import static ghidracli.function.FunctionVariables.describeType;
import static ghidracli.function.FunctionVariables.variableName;

/** Decompiler variable discovery and edits to their corresponding database definitions. */
public final class FunctionVariableCommands {
    private final ProgramSession session;
    private final FunctionVariables variables;
    private final TypeResolver typeResolver;

    public FunctionVariableCommands(ProgramSession session, FunctionQueries functionQueries,
            TypeResolver typeResolver) {
        this.session = session;
        this.variables = new FunctionVariables(session, functionQueries);
        this.typeResolver = typeResolver;
    }

    public JsonObject handleFunctionVarList(JsonObject args) {
        try {
            Function function = variables.function(args);
            List<HighSymbol> symbols = variables.decompile(function, args).symbols();
            JsonArray rows = new JsonArray();
            for (HighSymbol symbol : symbols) rows.add(describe(symbol));
            JsonObject result = context(function);
            result.add("project", variables.project());
            result.addProperty("program", session.programPath());
            result.addProperty("modification", variables.modification());
            result.add("variables", rows);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to list variables: " + e.getMessage(), e);
        }
    }

    public JsonObject handleFunctionVarGet(JsonObject args) {
        try {
            Function function = variables.function(args);
            String name = variableName(args);
            List<HighSymbol> symbols = variables.decompile(function, args).symbols();
            FunctionVariables.Selection selected = variables.select(function, symbols, name, args);
            if (selected.error() != null) return selected.error();
            JsonObject result = context(function);
            result.add("decompiler", describe(selected.symbol()));
            result.add("database", describeDatabase(function, savedVariable(function, selected.symbol())));
            return result;
        } catch (Exception e) {
            return errorResult("Failed to get variable: " + e.getMessage(), e);
        }
    }

    public JsonObject handleFunctionVarSet(JsonObject args) {
        try {
            Function function = variables.function(args);
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

            List<HighSymbol> symbols = variables.decompile(function, args).symbols();
            FunctionVariables.Selection selected = variables.select(function, symbols, name, args);
            if (selected.error() != null) return selected.error();
            HighSymbol target = selected.symbol();
            String effectiveName = newName != null ? newName : target.getName();
            Variable saved = savedVariable(function, target);
            if (saved instanceof Parameter parameter && parameter.isAutoParameter()) {
                return autoParameterError(function, parameter);
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

    private static JsonObject autoParameterError(Function function, Parameter parameter) {
        String message = "Cannot modify auto-parameter: " + parameter.getName();
        if (parameter.getAutoParameterType() != AutoParameterType.THIS) return errorResult(message);

        Namespace namespace = function.getParentNamespace();
        JsonObject namespaceContext = new JsonObject();
        namespaceContext.addProperty("path", namespace.getName(true));
        namespaceContext.addProperty("kind", namespace.isGlobal() ? "global"
            : namespace.getSymbol().getSymbolType().toString().toLowerCase(Locale.ROOT));
        JsonObject detail = context(function);
        detail.add("namespace", namespaceContext);
        detail.addProperty("calling_convention", function.getCallingConventionName());
        detail.add("parameter", describeDatabase(function, parameter));

        JsonObject error = errorResult(message
            + ". THIS is generated from the function's class namespace and calling convention."
            + " Choose the intended class; create it with namespace create --kind class if needed,"
            + " then move this function with symbol set-namespace using --namespace and --address."
            + " Inspect the resulting THIS type with function var get.");
        error.add("detail", detail);
        return error;
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
}
