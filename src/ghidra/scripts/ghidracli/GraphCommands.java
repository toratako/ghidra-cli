package ghidracli;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
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
            String funcAddr = func.getEntryPoint().toString();

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
                        edge.addProperty("to", targetAddr.toString());
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

    JsonObject handleGraphCallers(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String funcName = getArgString(args, "function");
        if (funcName == null) return errorResult("Function name required");
        int depth = getArgInt(args, "depth", 1);
        int limit = getArgInt(args, "limit", 0);

        Function targetFunc = functionQueries.findFunctionByNameOrAddress(funcName);
        if (targetFunc == null) return errorResult(functionQueries.buildFunctionTargetHint(funcName));

        ReferenceManager refMgr = session.program().getReferenceManager();
        FunctionManager fm = session.program().getFunctionManager();
        JsonArray callers = new JsonArray();
        Set<String> visited = new HashSet<>();

        findCallersRecursive(targetFunc, 0, depth, limit, callers, visited, refMgr, fm);

        JsonObject result = new JsonObject();
        result.addProperty("function", funcName);
        result.add("callers", callers);
        result.addProperty("count", callers.size());
        return result;
    }

    private boolean graphLimitReached(JsonArray rows, int limit) {
        return limit > 0 && rows.size() >= limit;
    }

    private void findCallersRecursive(Function func, int currentDepth, int maxDepth, int limit,
            JsonArray callers, Set<String> visited, ReferenceManager refMgr, FunctionManager fm) {
        if (graphLimitReached(callers, limit)) return;
        if (maxDepth > 0 && currentDepth >= maxDepth) return;
        String funcAddrStr = func.getEntryPoint().toString();
        if (visited.contains(funcAddrStr)) return;
        visited.add(funcAddrStr);

        for (Reference ref : refMgr.getReferencesTo(func.getEntryPoint())) {
            if (graphLimitReached(callers, limit)) return;
            RefType refType = ref.getReferenceType();
            if (refType.isCall() || refType == RefType.PARAM || refType == RefType.INDIRECTION) {
                Address fromAddr = ref.getFromAddress();
                Function callerFunc = fm.getFunctionContaining(fromAddr);
                if (callerFunc != null) {
                    JsonObject callerInfo = new JsonObject();
                    callerInfo.addProperty("name", callerFunc.getName());
                    callerInfo.addProperty("address", callerFunc.getEntryPoint().toString());
                    callerInfo.addProperty("call_site", fromAddr.toString());
                    callerInfo.addProperty("depth", currentDepth);
                    callers.add(callerInfo);

                    if (graphLimitReached(callers, limit)) return;
                    if (maxDepth == 0 || currentDepth + 1 < maxDepth) {
                        findCallersRecursive(
                            callerFunc, currentDepth + 1, maxDepth, limit,
                            callers, visited, refMgr, fm);
                        if (graphLimitReached(callers, limit)) return;
                    }
                }
            }
        }
    }

    JsonObject handleGraphCallees(JsonObject args) {
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
        Set<String> visited = new HashSet<>();

        findCalleesRecursive(targetFunc, 0, depth, limit, callees, visited, refMgr, fm);

        JsonObject result = new JsonObject();
        result.addProperty("function", funcName);
        result.add("callees", callees);
        result.addProperty("count", callees.size());
        return result;
    }

    private void findCalleesRecursive(Function func, int currentDepth, int maxDepth, int limit,
            JsonArray callees, Set<String> visited, ReferenceManager refMgr, FunctionManager fm) {
        if (graphLimitReached(callees, limit)) return;
        if (maxDepth > 0 && currentDepth >= maxDepth) return;
        String funcAddrStr = func.getEntryPoint().toString();
        if (visited.contains(funcAddrStr)) return;
        visited.add(funcAddrStr);

        ghidra.program.model.address.AddressIterator refSrcIter =
            refMgr.getReferenceSourceIterator(func.getBody(), true);
        while (refSrcIter.hasNext()) {
            if (graphLimitReached(callees, limit)) return;
            Address fromAddr = refSrcIter.next();
            for (Reference ref : refMgr.getReferencesFrom(fromAddr)) {
                if (graphLimitReached(callees, limit)) return;
                if (ref.getReferenceType().isCall()) {
                    Address toAddr = ref.getToAddress();
                    Function calleeFunc = fm.getFunctionAt(toAddr);
                    if (calleeFunc != null) {
                        JsonObject calleeInfo = new JsonObject();
                        calleeInfo.addProperty("name", calleeFunc.getName());
                        calleeInfo.addProperty("address", calleeFunc.getEntryPoint().toString());
                        calleeInfo.addProperty("call_site", ref.getFromAddress().toString());
                        calleeInfo.addProperty("depth", currentDepth);
                        callees.add(calleeInfo);

                        if (graphLimitReached(callees, limit)) return;
                        if (maxDepth == 0 || currentDepth + 1 < maxDepth) {
                            findCalleesRecursive(
                                calleeFunc, currentDepth + 1, maxDepth, limit,
                                callees, visited, refMgr, fm);
                            if (graphLimitReached(callees, limit)) return;
                        }
                    }
                }
            }
        }
    }

    JsonObject handleGraphExport(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String format = getArgString(args, "format");
        if (format == null) format = "json";

        // Build graph first
        JsonObject graphData = handleGraphCalls(new JsonObject());
        if (graphData.has("error")) return graphData;

        if ("json".equals(format)) {
            return graphData;
        } else if ("dot".equals(format)) {
            StringBuilder sb = new StringBuilder();
            sb.append("digraph CallGraph {\n");
            sb.append("  rankdir=LR;\n");
            sb.append("  node [shape=box];\n");

            JsonArray nodes = graphData.getAsJsonArray("nodes");
            for (int i = 0; i < nodes.size(); i++) {
                JsonObject node = nodes.get(i).getAsJsonObject();
                String nodeId = node.get("id").getAsString().replace(":", "_");
                String label = node.get("name").getAsString();
                sb.append("  \"").append(nodeId).append("\" [label=\"").append(label).append("\"];\n");
            }

            JsonArray edges = graphData.getAsJsonArray("edges");
            for (int i = 0; i < edges.size(); i++) {
                JsonObject edge = edges.get(i).getAsJsonObject();
                String fromId = edge.get("from").getAsString().replace(":", "_");
                String toId = edge.get("to").getAsString().replace(":", "_");
                sb.append("  \"").append(fromId).append("\" -> \"").append(toId).append("\";\n");
            }

            sb.append("}");

            JsonObject result = new JsonObject();
            result.addProperty("format", "dot");
            result.addProperty("output", sb.toString());
            return result;
        } else {
            return errorResult("Unsupported format: " + format);
        }
    }
}
