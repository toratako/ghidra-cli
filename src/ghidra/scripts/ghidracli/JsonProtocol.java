package ghidracli;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

/** JSON arguments and response envelopes shared by the bridge. */
final class JsonProtocol {
    private JsonProtocol() {}

    static JsonObject successResponse(JsonObject data) {
        JsonObject resp = new JsonObject();
        resp.addProperty("status", "success");
        resp.add("data", data);
        return resp;
    }

    static JsonObject errorResponse(String message) {
        return errorResponse(message, null);
    }

    /** Error envelope with optional structured conflict/diagnostic detail. */
    static JsonObject errorResponse(String message, JsonObject detail) {
        JsonObject resp = new JsonObject();
        resp.addProperty("status", "error");
        resp.addProperty("message", message);
        if (detail != null) {
            resp.add("detail", detail);
        }
        return resp;
    }

    static JsonObject errorResult(String message) {
        JsonObject result = new JsonObject();
        result.addProperty("error", message);
        return result;
    }

    static String getArgString(JsonObject args, String key) {
        if (args == null || !args.has(key) || args.get(key).isJsonNull()) return null;
        return args.get(key).getAsString();
    }

    static int getArgInt(JsonObject args, String key, int defaultVal) {
        if (args == null || !args.has(key) || args.get(key).isJsonNull()) return defaultVal;
        return args.get(key).getAsInt();
    }

    static boolean getArgBool(JsonObject args, String key, boolean defaultVal) {
        if (args == null || !args.has(key) || args.get(key).isJsonNull()) return defaultVal;
        return args.get(key).getAsBoolean();
    }

    static String[] getArgStringArray(JsonObject args, String key) {
        if (args == null || !args.has(key) || !args.get(key).isJsonArray()) return new String[0];
        JsonArray arr = args.getAsJsonArray(key);
        String[] out = new String[arr.size()];
        for (int i = 0; i < arr.size(); i++) out[i] = arr.get(i).getAsString();
        return out;
    }

    static JsonArray toJsonArray(String[] values) {
        JsonArray arr = new JsonArray();
        for (String v : values) arr.add(v);
        return arr;
    }
}
