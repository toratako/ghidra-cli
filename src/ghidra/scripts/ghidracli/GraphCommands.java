package ghidracli;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.exception.CancelledException;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashSet;
import java.util.Set;
import static ghidracli.JsonProtocol.errorResult;
import static ghidracli.JsonProtocol.getArgInt;
import static ghidracli.JsonProtocol.getArgString;

final class GraphCommands {
    private final ProgramSession session;
    private final FunctionQueries functionQueries;

    GraphCommands(ProgramSession session, FunctionQueries functionQueries) {
        this.session = session;
        this.functionQueries = functionQueries;
    }

    JsonObject handleGraphCalls(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        int limit = getArgInt(args, "limit", 0);

        FunctionManager fm = session.program().getFunctionManager();
        ReferenceManager refMgr = session.program().getReferenceManager();
        JsonArray nodes = new JsonArray();
        JsonArray edges = new JsonArray();
        int count = 0;

        FunctionIterator iter = fm.getFunctions(true);
        while (iter.hasNext()) {
            if (limit > 0 && count >= limit) break;
            Function func = iter.next();
            String funcAddr = AddressCodec.format(func.getEntryPoint());

            JsonObject node = new JsonObject();
            node.addProperty("id", funcAddr);
            node.addProperty("name", func.getName());
            node.addProperty("address", funcAddr);
            nodes.add(node);

            ghidra.program.model.address.AddressIterator refSrcIter =
                refMgr.getReferenceSourceIterator(func.getBody(), true);
            while (refSrcIter.hasNext()) {
                Address fromAddr = refSrcIter.next();
                for (Reference ref : refMgr.getReferencesFrom(fromAddr)) {
                if (ref.getReferenceType().isCall()) {
                    Address targetAddr = ref.getToAddress();
                    Function targetFunc = fm.getFunctionAt(targetAddr);
                    if (targetFunc != null) {
                        JsonObject edge = new JsonObject();
                        edge.addProperty("from", funcAddr);
                        edge.addProperty("to", AddressCodec.format(targetAddr));
                        edge.addProperty("type", "call");
                        edges.add(edge);
                    }
                }
                }
            }
            count++;
        }

        JsonObject result = new JsonObject();
        result.add("nodes", nodes);
        result.add("edges", edges);
        result.addProperty("node_count", nodes.size());
        result.addProperty("edge_count", edges.size());
        return result;
    }

    JsonObject handleGraphCallers(JsonObject args) throws CancelledException {
        if (session.program() == null) return errorResult("No program loaded");

        String funcName = getArgString(args, "function");
        if (funcName == null) return errorResult("Function name required");
        int depth = getArgInt(args, "depth", 1);
        int limit = getArgInt(args, "limit", 0);

        CallReferences calls = new CallReferences(session, new AddressResolver(session));
        Function targetFunc = calls.resolveTarget(funcName);
        if (targetFunc == null) return errorResult(functionQueries.buildFunctionTargetHint(funcName));

        FunctionManager fm = session.program().getFunctionManager();
        JsonArray callers = new JsonArray();
        findCallers(targetFunc, depth, limit, callers, calls, fm);

        JsonObject result = new JsonObject();
        result.addProperty("function", AddressCodec.isExplicit(funcName)
            ? AddressCodec.format(targetFunc.getEntryPoint()) : funcName);
        result.add("callers", callers);
        result.addProperty("count", callers.size());
        return result;
    }

    private boolean graphLimitReached(JsonArray rows, int limit) {
        return limit > 0 && rows.size() >= limit;
    }

    private void findCallers(Function root, int maxDepth, int limit,
            JsonArray callers, CallReferences calls, FunctionManager fm) throws CancelledException {
        Deque<Function> pending = new ArrayDeque<>();
        Set<Address> visited = new HashSet<>();
        pending.addLast(root);
        visited.add(root.getEntryPoint());

        // Expand each function at its shortest distance from the root. A longer
        // path visited first must not consume the depth budget of a later shortcut.
        for (int currentDepth = 0; !pending.isEmpty(); currentDepth++) {
            int levelSize = pending.size();
            for (int i = 0; i < levelSize; i++) {
                session.monitor().checkCancelled();
                Function func = pending.removeFirst();
                int rowDepth = currentDepth;
                boolean completed = calls.visitCallsTo(func, (ref, destination) -> {
                    Address fromAddr = ref.getFromAddress();
                    Function callerFunc = fm.getFunctionContaining(fromAddr);
                    if (callerFunc == null) return true;

                    JsonObject callerInfo = new JsonObject();
                    callerInfo.addProperty("name", callerFunc.getName());
                    callerInfo.addProperty("address", AddressCodec.format(callerFunc.getEntryPoint()));
                    callerInfo.addProperty("call_site", AddressCodec.format(fromAddr));
                    callerInfo.addProperty("depth", rowDepth);
                    callers.add(callerInfo);

                    if (graphLimitReached(callers, limit)) return false;
                    if ((maxDepth == 0 || rowDepth + 1 < maxDepth)
                            && visited.add(callerFunc.getEntryPoint())) {
                        pending.addLast(callerFunc);
                    }
                    return true;
                });
                if (!completed) return;
            }
        }
    }

    JsonObject handleGraphCallees(JsonObject args) throws CancelledException {
        if (session.program() == null) return errorResult("No program loaded");

        String funcName = getArgString(args, "function");
        if (funcName == null) return errorResult("Function name required");
        int depth = getArgInt(args, "depth", 1);
        int limit = getArgInt(args, "limit", 0);

        Function targetFunc = functionQueries.findFunctionByNameOrAddress(funcName);
        if (targetFunc == null) return errorResult(functionQueries.buildFunctionTargetHint(funcName));

        ReferenceManager refMgr = session.program().getReferenceManager();
        FunctionManager fm = session.program().getFunctionManager();
        JsonArray callees = new JsonArray();
        findCallees(targetFunc, depth, limit, callees, refMgr, fm);

        JsonObject result = new JsonObject();
        result.addProperty("function", AddressCodec.isExplicit(funcName)
            ? AddressCodec.format(targetFunc.getEntryPoint()) : funcName);
        result.add("callees", callees);
        result.addProperty("count", callees.size());
        return result;
    }

    private void findCallees(Function root, int maxDepth, int limit,
            JsonArray callees, ReferenceManager refMgr, FunctionManager fm) throws CancelledException {
        Deque<Function> pending = new ArrayDeque<>();
        Set<Address> visited = new HashSet<>();
        pending.addLast(root);
        visited.add(root.getEntryPoint());

        for (int currentDepth = 0; !pending.isEmpty(); currentDepth++) {
            int levelSize = pending.size();
            for (int i = 0; i < levelSize; i++) {
                session.monitor().checkCancelled();
                Function func = pending.removeFirst();
                ghidra.program.model.address.AddressIterator refSrcIter =
                    refMgr.getReferenceSourceIterator(func.getBody(), true);
                while (refSrcIter.hasNext()) {
                    session.monitor().checkCancelled();
                    Address fromAddr = refSrcIter.next();
                    for (Reference ref : refMgr.getReferencesFrom(fromAddr)) {
                        session.monitor().checkCancelled();
                        if (ref.getReferenceType().isCall()) {
                            Address toAddr = ref.getToAddress();
                            Function calleeFunc = fm.getFunctionAt(toAddr);
                            if (calleeFunc == null) continue;

                            JsonObject calleeInfo = new JsonObject();
                            calleeInfo.addProperty("name", calleeFunc.getName());
                            calleeInfo.addProperty("address", AddressCodec.format(calleeFunc.getEntryPoint()));
                            calleeInfo.addProperty("call_site", AddressCodec.format(ref.getFromAddress()));
                            calleeInfo.addProperty("depth", currentDepth);
                            callees.add(calleeInfo);

                            if (graphLimitReached(callees, limit)) return;
                            if ((maxDepth == 0 || currentDepth + 1 < maxDepth)
                                    && visited.add(calleeFunc.getEntryPoint())) {
                                pending.addLast(calleeFunc);
                            }
                        }
                    }
                }
            }
        }
    }

}
