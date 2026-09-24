package ghidracli.protocol;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

/** JSON arguments and response envelopes shared by the bridge. */
public final class JsonProtocol {
    private JsonProtocol() {}

    /** A validation failure with diagnostics that survive handler boundaries. */
    public static class CommandException extends IllegalArgumentException {
        private final JsonObject detail;

        public CommandException(String message, JsonObject detail) {
            super(message);
            this.detail = detail;
        }

        JsonObject detail() { return detail; }
    }

    public static JsonObject successResponse(JsonObject data) {
        JsonObject resp = new JsonObject();
        resp.addProperty("status", "success");
        resp.add("data", data);
        return resp;
    }

    public static JsonObject errorResponse(String message) {
        return errorResponse(message, null);
    }

    /** Error envelope with optional structured conflict/diagnostic detail. */
    public static JsonObject errorResponse(String message, JsonObject detail) {
        JsonObject resp = new JsonObject();
        resp.addProperty("status", "error");
        resp.addProperty("message", message);
        if (detail != null) {
            resp.add("detail", detail);
        }
        return resp;
    }

    public static JsonObject errorResult(String message) {
        JsonObject result = new JsonObject();
        result.addProperty("error", message);
        return result;
    }

    public static JsonObject errorResult(String message, Throwable cause) {
        JsonObject result = errorResult(message);
        JsonObject detail = errorDetail(cause);
        if (detail != null) result.add("detail", detail);
        return result;
    }

    public static JsonObject errorDetail(Throwable cause) {
        return cause instanceof CommandException ? ((CommandException) cause).detail() : null;
    }

    /** VM failures and forced thread termination cannot be safely returned as job errors. */
    public static boolean isFatalError(Error error) {
        return error instanceof VirtualMachineError || error instanceof ThreadDeath;
    }

    public static String getArgString(JsonObject args, String key) {
        if (args == null || !args.has(key) || args.get(key).isJsonNull()) return null;
        return args.get(key).getAsString();
    }

    public static int getArgInt(JsonObject args, String key, int defaultVal) {
        if (args == null || !args.has(key) || args.get(key).isJsonNull()) return defaultVal;
        return args.get(key).getAsInt();
    }

    /** Checked nonnegative int; omitted/null values retain the command's default. */
    public static int getNonnegativeIntArg(JsonObject args, String name, int defaultVal) {
        if (args == null || !args.has(name) || args.get(name).isJsonNull()) return defaultVal;
        JsonElement value = args.get(name);
        try {
            if (value.isJsonPrimitive() && value.getAsJsonPrimitive().isNumber()) {
                int number = value.getAsBigDecimal().intValueExact();
                if (number >= 0) return number;
            }
        } catch (ArithmeticException | NumberFormatException e) {
            // Reject fractional and overflowing values instead of narrowing them.
        }
        throw new IllegalArgumentException(name + " must be an integer from 0 to " + Integer.MAX_VALUE);
    }

    /** Ghidra multiplies native timeout seconds by 1000 in a signed int. */
    public static int getDecompileTimeoutArg(JsonObject args) {
        int maxSeconds = Integer.MAX_VALUE / 1000;
        String message = "timeout_secs must be an integer from 0 to " + maxSeconds;
        int seconds;
        try {
            seconds = getNonnegativeIntArg(args, "timeout_secs", 0);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(message, e);
        }
        if (seconds > maxSeconds) throw new IllegalArgumentException(message);
        return seconds;
    }

    /** Checked nonnegative integer; an omitted/null value defaults to zero. */
    public static long getNonnegativeLongArg(JsonObject args, String name) {
        if (args == null || !args.has(name) || args.get(name).isJsonNull()) return 0;
        JsonElement value = args.get(name);
        try {
            if (value.isJsonPrimitive() && value.getAsJsonPrimitive().isNumber()) {
                long number = value.getAsBigDecimal().longValueExact();
                if (number >= 0) return number;
            }
        } catch (ArithmeticException | NumberFormatException e) {
            // Reject fractional and overflowing values instead of narrowing them.
        }
        throw new IllegalArgumentException(name + " must be an integer from 0 to " + Long.MAX_VALUE);
    }

    public static boolean getArgBool(JsonObject args, String key, boolean defaultVal) {
        if (args == null || !args.has(key) || args.get(key).isJsonNull()) return defaultVal;
        return args.get(key).getAsBoolean();
    }

    public static String[] getArgStringArray(JsonObject args, String key) {
        if (args == null || !args.has(key) || !args.get(key).isJsonArray()) return new String[0];
        JsonArray arr = args.getAsJsonArray(key);
        String[] out = new String[arr.size()];
        for (int i = 0; i < arr.size(); i++) out[i] = arr.get(i).getAsString();
        return out;
    }

    public static JsonArray toJsonArray(String[] values) {
        JsonArray arr = new JsonArray();
        for (String v : values) arr.add(v);
        return arr;
    }
}
