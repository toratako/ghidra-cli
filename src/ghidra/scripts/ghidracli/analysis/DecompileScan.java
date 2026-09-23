package ghidracli.analysis;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.CancelledException;
import ghidracli.function.FunctionQueries;
import ghidracli.query.AddressCodec;
import ghidracli.query.ListQuery;
import ghidracli.session.ProgramSession;
import java.util.ArrayList;
import java.util.List;

import static ghidracli.protocol.JsonProtocol.getArgString;
import static ghidracli.protocol.JsonProtocol.getDecompileTimeoutArg;

/** Request-local semantic scan using the session-owned native decompiler. */
final class DecompileScan {
    record Findings(JsonArray rows, JsonArray unresolved) {}

    @FunctionalInterface
    interface Inspector {
        Findings inspect(Function function, DecompileResults results) throws Exception;
    }

    private final ProgramSession session;
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

    DecompileScan(ProgramSession session, FunctionQueries functionQueries,
            JsonObject args, String scopeKey) throws CancelledException {
        this.session = session;
        limit = ListQuery.pageArgument(args, "limit");
        timeoutSecs = getDecompileTimeoutArg(args);
        String selector = getArgString(args, scopeKey);
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

    private static boolean eligible(Function function) {
        return !function.isExternal() && !function.getBody().isEmpty();
    }

    void run(Inspector inspect) throws Exception {
        for (Function function : functions) {
            session.monitor().checkCancelled();
            if (limit > 0 && rows.size() >= limit) break;
            visited++;
            // Native decompilation can report completion for a fabricated
            // bad-instruction body when no listing instruction exists.
            // That does not establish an absence of semantic findings.
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
            for (JsonElement row : findings.rows()) {
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

    JsonArray rows() {
        return rows;
    }

    JsonArray unresolved() {
        return unresolved;
    }

    JsonObject scan(String omittedKey) {
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
        scan.addProperty(omittedKey, omitted);
        return scan;
    }

    JsonElement scope() {
        return selected == null ? JsonNull.INSTANCE : context(selected);
    }

    private static JsonObject context(Function function) {
        JsonObject context = new JsonObject();
        context.addProperty("function", function.getName(true));
        context.addProperty("address", AddressCodec.format(function.getEntryPoint()));
        return context;
    }
}
