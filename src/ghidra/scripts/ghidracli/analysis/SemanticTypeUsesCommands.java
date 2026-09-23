package ghidracli.analysis;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.EquateSymbol;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.UnionFacetSymbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.CancelledException;
import ghidracli.function.FunctionQueries;
import ghidracli.query.AddressCodec;
import ghidracli.query.ListQuery;
import ghidracli.session.ProgramSession;
import ghidracli.types.StructureFields;
import ghidracli.types.TypeFieldTarget;
import ghidracli.types.TypeResolver;
import ghidracli.types.TypeUseMatcher;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Set;

import static ghidracli.protocol.JsonProtocol.errorResult;
import static ghidracli.protocol.JsonProtocol.getArgString;
import static ghidracli.protocol.JsonProtocol.getDecompileTimeoutArg;

/** Fresh semantic searches, serialized on ProgramSession's original program thread. */
public final class SemanticTypeUsesCommands {
    private final ProgramSession session;
    private final TypeResolver resolver;
    private final FunctionQueries functionQueries;

    public SemanticTypeUsesCommands(ProgramSession session, TypeResolver resolver,
            FunctionQueries functionQueries) {
        this.session = session;
        this.resolver = resolver;
        this.functionQueries = functionQueries;
    }

    public JsonObject handleVariables(JsonObject args) throws Exception {
        if (session.program() == null) return errorResult("No program loaded");
        String kind = getArgString(args, "kind");
        if (kind != null && !kind.equals("variable")) {
            throw new IllegalArgumentException("Semantic variable search requires kind variable");
        }
        DataType target = target(args);
        Search search = new Search(args);
        TypeUseMatcher matcher = new TypeUseMatcher(session, target);
        search.run((function, results) -> new Findings(variables(function, results, matcher), new JsonArray()));
        JsonObject result = search.result(target);
        JsonArray kinds = new JsonArray();
        kinds.add("variable");
        result.add("kinds", kinds);
        return result;
    }

    public JsonObject handleFields(JsonObject args) throws Exception {
        if (session.program() == null) return errorResult("No program loaded");
        DataType target = target(args);
        DataTypeComponent field = TypeFieldTarget.resolve(target, args);
        Search search = new Search(args);
        search.run((function, results) -> {
            FieldUses.Findings findings = FieldUses.find(session, function, results, field);
            return new Findings(findings.uses(), findings.unresolved());
        });
        JsonObject result = search.result(target);
        result.add("target_field", StructureFields.describe(field));
        JsonObject scan = result.getAsJsonObject("scan");
        scan.add("unresolved", search.unresolved);
        return result;
    }

    private DataType target(JsonObject args) throws CancelledException {
        String name = getArgString(args, "type_name");
        if (name == null || name.isBlank()) throw new IllegalArgumentException("Type name required");
        session.monitor().checkCancelled();
        DataType target = resolver.resolveRegisteredDataType(name);
        if (target == null) throw new IllegalArgumentException("Registered type not found: " + name);
        return target;
    }

    private JsonArray variables(Function function, DecompileResults results, TypeUseMatcher matcher)
            throws CancelledException {
        JsonArray rows = new JsonArray();
        Set<HighSymbol> visited = Collections.newSetFromMap(new IdentityHashMap<>());
        var symbols = results.getHighFunction().getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            session.monitor().checkCancelled();
            HighSymbol symbol = symbols.next();
            // The local map also includes constants and union-field annotations.
            if (!visited.add(symbol) || symbol.isGlobal() || symbol instanceof EquateSymbol
                    || symbol instanceof UnionFacetSymbol) continue;
            JsonObject row = matcher.match(symbol.getDataType());
            if (row == null) continue;
            row.addProperty("kind", "variable");
            row.addProperty("role", symbol.isParameter() ? "parameter" : "local");
            row.addProperty("function", function.getName(true));
            row.addProperty("address", AddressCodec.format(function.getEntryPoint()));
            row.addProperty("name", symbol.getName());
            row.addProperty("storage", symbol.getStorage().toString());
            if (symbol.isParameter()) {
                row.addProperty("ordinal", symbol.getCategoryIndex());
            } else {
                row.addProperty("first_use", symbol.getPCAddress() == null
                    ? null : AddressCodec.format(symbol.getPCAddress()));
            }
            row.addProperty("evidence", "decompiler");
            rows.add(row);
        }
        return rows;
    }

    private static JsonObject context(Function function) {
        JsonObject context = new JsonObject();
        context.addProperty("function", function.getName(true));
        context.addProperty("address", AddressCodec.format(function.getEntryPoint()));
        return context;
    }

    private record Findings(JsonArray uses, JsonArray unresolved) {}

    @FunctionalInterface
    private interface InspectFunction {
        Findings inspect(Function function, DecompileResults results) throws Exception;
    }

    /** All state, including native objects and decompilations, dies with this request. */
    private final class Search {
        private final long limit;
        private final int timeoutSecs;
        private final Function selected;
        private final List<Function> functions = new ArrayList<>();
        private final JsonArray rows = new JsonArray();
        private final JsonArray failed = new JsonArray();
        private final JsonArray warnings = new JsonArray();
        private final JsonArray unresolved = new JsonArray();
        private int visited;
        private int successful;
        private long omitted;

        Search(JsonObject args) throws CancelledException {
            limit = ListQuery.pageArgument(args, "limit");
            timeoutSecs = getDecompileTimeoutArg(args);
            String selector = getArgString(args, "function");
            if (selector != null) {
                if (selector.isBlank()) throw new IllegalArgumentException("Function selector must not be empty");
                selected = functionQueries.findFunctionByNameOrAddress(selector);
                if (selected == null) {
                    throw new IllegalArgumentException(functionQueries.buildFunctionTargetHint(selector));
                }
                if (!eligible(selected)) {
                    throw new IllegalArgumentException("Function has no internal body to decompile: " + selector);
                }
                functions.add(selected);
            } else {
                selected = null;
                // Include unmapped internal bodies too: they may fail native
                // decompilation, and must remain visible in scan coverage.
                var symbols = session.program().getSymbolTable().getSymbols(null, SymbolType.FUNCTION, true);
                var manager = session.program().getFunctionManager();
                while (symbols.hasNext()) {
                    session.monitor().checkCancelled();
                    Function function = manager.getFunction(symbols.next().getID());
                    if (eligible(function)) functions.add(function);
                }
            }
            session.monitor().checkCancelled();
        }

        private boolean eligible(Function function) {
            return !function.isExternal() && !function.getBody().isEmpty();
        }

        void run(InspectFunction inspect) throws Exception {
            for (Function function : functions) {
                session.monitor().checkCancelled();
                if (limit > 0 && rows.size() >= limit) break;
                visited++;
                // Native decompilation can report completion for a fabricated
                // bad-instruction body when no listing instruction exists.
                // That does not establish an absence of semantic type uses.
                if (session.program().getListing().getInstructionAt(function.getEntryPoint()) == null) {
                    failure(function, "missing_instructions", "No listing instruction at the function entry");
                    continue;
                }
                DecompileResults results = session.decompile(function, timeoutSecs);
                session.monitor().checkCancelled();
                if (results.isCancelled()) throw new CancelledException();
                if (!results.decompileCompleted() || results.getHighFunction() == null) {
                    String reason = results.isTimedOut() ? "timeout"
                        : results.failedToStart() ? "failed_to_start"
                        : !results.decompileCompleted() ? "decompile_failed" : "missing_high_function";
                    String message = results.getErrorMessage();
                    failure(function, reason, message == null || message.isBlank()
                        ? (reason.equals("missing_high_function")
                            ? "Decompiler returned no high-level function" : "No diagnostic returned by Ghidra")
                        : message.trim());
                    continue;
                }
                session.monitor().checkCancelled();
                JsonArray diagnostics = DecompileWarnings.collect(results);
                session.monitor().checkCancelled();
                if (!diagnostics.isEmpty()) {
                    JsonObject entry = context(function);
                    entry.add("warnings", diagnostics);
                    warnings.add(entry);
                }
                // Successful decompilations can carry recoverable warnings or
                // user C comments; retain them without inferring failure from
                // arbitrary message text. Unexpected exceptions still propagate.
                Findings findings = inspect.inspect(function, results);
                successful++;
                unresolved.addAll(findings.unresolved());
                for (JsonElement row : findings.uses()) {
                    session.monitor().checkCancelled();
                    if (limit > 0 && rows.size() >= limit) omitted++;
                    else rows.add(row);
                }
            }
            session.monitor().checkCancelled();
        }

        private void failure(Function function, String reason, String message) {
            JsonObject failure = context(function);
            failure.addProperty("reason", reason);
            failure.addProperty("message", message);
            failed.add(failure);
        }

        JsonObject result(DataType target) {
            int unvisited = functions.size() - visited;
            boolean limited = unvisited > 0 || omitted > 0;
            JsonObject scan = new JsonObject();
            scan.addProperty("complete", !limited && failed.isEmpty() && unresolved.isEmpty());
            scan.addProperty("stop_reason", limited ? "limit" : !failed.isEmpty() ? "decompile_failed" : null);
            scan.addProperty("total_functions", functions.size());
            scan.addProperty("visited_functions", visited);
            scan.addProperty("successful_functions", successful);
            scan.add("failed_functions", failed);
            scan.add("warnings", warnings);
            scan.addProperty("unvisited_functions", unvisited);
            scan.addProperty("omitted_uses", omitted);
            JsonObject result = new JsonObject();
            result.addProperty("target_type_path", target.getPathName());
            result.add("scope", selected == null ? JsonNull.INSTANCE : context(selected));
            result.add("scan", scan);
            result.add("uses", rows);
            return result;
        }
    }
}
