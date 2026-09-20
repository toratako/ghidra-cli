package ghidracli;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.util.exception.CancelledException;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Predicate;
import static ghidracli.JsonProtocol.errorResult;
import static ghidracli.JsonProtocol.getNonnegativeIntArg;
import static ghidracli.JsonProtocol.getArgString;

final class GraphCommands {
    private final ProgramSession session;
    private final FunctionQueries functionQueries;
    private final CallReferences calls;

    GraphCommands(ProgramSession session, FunctionQueries functionQueries) {
        this.session = session;
        this.functionQueries = functionQueries;
        this.calls = new CallReferences(session, new AddressResolver(session));
    }

    JsonObject handleGraphCalls(JsonObject args) throws CancelledException {
        if (session.program() == null) return errorResult("No program loaded");
        int limit = getNonnegativeIntArg(args, "limit", 0);
        JsonArray nodes = new JsonArray();
        JsonArray edges = new JsonArray();
        FunctionIterator iter = session.program().getFunctionManager().getFunctions(true);
        while (iter.hasNext() && (limit == 0 || nodes.size() < limit)) {
            session.monitor().checkCancelled();
            Function func = iter.next();
            String address = AddressCodec.format(func.getEntryPoint());
            JsonObject node = new JsonObject();
            node.addProperty("id", address);
            node.addProperty("name", func.getName());
            node.addProperty("address", address);
            nodes.add(node);
            calls.visitCallsFrom(func, call -> {
                JsonObject edge = call.toJson();
                edge.addProperty("from", address);
                edge.addProperty("to", AddressCodec.format(call.callee().address()));
                edges.add(edge);
                return true;
            });
        }
        JsonObject result = new JsonObject();
        result.add("nodes", nodes);
        result.add("edges", edges);
        result.addProperty("node_count", nodes.size());
        result.addProperty("edge_count", edges.size());
        return result;
    }

    JsonObject handleGraphCallers(JsonObject args) throws CancelledException {
        return traverse(args, true);
    }

    JsonObject handleGraphCallees(JsonObject args) throws CancelledException {
        return traverse(args, false);
    }

    private JsonObject traverse(JsonObject args, boolean incoming) throws CancelledException {
        if (session.program() == null) return errorResult("No program loaded");
        String target = getArgString(args, "function");
        if (target == null || target.isBlank()) return errorResult("Call target required");
        int depth = getNonnegativeIntArg(args, "depth", 1);
        int limit = getNonnegativeIntArg(args, "limit", 0);
        CallReferences.Endpoint root;
        if (incoming) {
            root = calls.resolveTarget(target);
        } else {
            // Outgoing queries inspect the selected body, including a thunk's own body.
            Function function = functionQueries.findFunctionByNameOrAddress(target);
            root = function == null ? null
                : new CallReferences.Endpoint(function.getEntryPoint(), function);
        }
        if (root == null) return errorResult(functionQueries.buildFunctionTargetHint(target));
        JsonArray rows = new JsonArray();
        visit(root, incoming, depth, limit, rows);
        JsonObject result = new JsonObject();
        result.addProperty("target", AddressCodec.isExplicit(target)
            ? AddressCodec.format(root.address()) : target);
        result.add("calls", rows);
        result.addProperty("count", rows.size());
        return result;
    }

    private void visit(CallReferences.Endpoint root, boolean incoming, int maxDepth, int limit,
            JsonArray rows) throws CancelledException {
        Deque<CallReferences.Endpoint> pending = new ArrayDeque<>();
        Set<Address> visited = new HashSet<>();
        pending.addLast(root);
        visited.add(root.address());
        // BFS expands each function at its shortest distance; cycles do not expand it twice.
        for (int currentDepth = 0; !pending.isEmpty(); currentDepth++) {
            int levelSize = pending.size();
            for (int i = 0; i < levelSize; i++) {
                session.monitor().checkCancelled();
                CallReferences.Endpoint endpoint = pending.removeFirst();
                int rowDepth = currentDepth;
                Predicate<CallReferences.Call> visitor = call -> {
                    JsonObject row = call.toJson();
                    row.addProperty("depth", rowDepth);
                    rows.add(row);
                    if (limit > 0 && rows.size() >= limit) return false;
                    Function nextFunction = incoming ? call.caller() : call.callee().function();
                    if (nextFunction != null && (maxDepth == 0 || rowDepth + 1 < maxDepth)) {
                        CallReferences.Endpoint next = incoming ? calls.canonical(nextFunction) : call.callee();
                        if (visited.add(next.address())) pending.addLast(next);
                    }
                    return true;
                };
                boolean completed = incoming ? calls.visitCallsTo(endpoint, visitor)
                    : calls.visitCallsFrom(endpoint.function(), visitor);
                if (!completed) return;
            }
        }
    }
}
