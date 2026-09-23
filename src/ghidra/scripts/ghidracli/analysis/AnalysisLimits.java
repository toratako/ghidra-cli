package ghidracli.analysis;

import com.google.gson.JsonObject;
import ghidracli.protocol.JsonProtocol;

/** Output budgets; neither budget limits native analysis or indexing work. */
record AnalysisLimits(int maxNodes, int maxEdges) {
    static AnalysisLimits from(JsonObject args) {
        return new AnalysisLimits(positive(args, "max_nodes", 1000),
            positive(args, "max_edges", 4000));
    }

    private static int positive(JsonObject args, String key, int defaultValue) {
        int value = JsonProtocol.getNonnegativeIntArg(args, key, defaultValue);
        if (value == 0) {
            throw new IllegalArgumentException(key + " must be an integer from 1 to " + Integer.MAX_VALUE);
        }
        return value;
    }

    JsonObject toJson(String nodeUnit, String edgeUnit) {
        JsonObject result = new JsonObject();
        result.addProperty("max_nodes", maxNodes);
        result.addProperty("max_edges", maxEdges);
        result.addProperty("node_unit", nodeUnit);
        result.addProperty("edge_unit", edgeUnit);
        return result;
    }
}
