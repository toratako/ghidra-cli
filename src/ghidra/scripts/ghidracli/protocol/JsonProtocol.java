package ghidracli.protocol;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import java.io.IOException;
import java.io.StringReader;

/** JSON arguments and response envelopes shared by the bridge. */
public final class JsonProtocol {
  private JsonProtocol() {}

  /** Reject ambiguous or non-JSON requests before selecting a Program or control. */
  @SuppressWarnings("deprecation") // Ghidra 11 includes Gson predating Strictness.
  public static JsonObject parseRequest(String line) {
    validateRequestTokens(line);
    try (JsonReader reader = new JsonReader(new StringReader(line))) {
      // JsonParser.parseReader changes this setting, so consume tokens directly.
      reader.setLenient(false);
      JsonElement request = readRequestValue(reader);
      if (!request.isJsonObject() || reader.peek() != JsonToken.END_DOCUMENT) {
        throw new IllegalArgumentException("Request must be one JSON object");
      }
      return request.getAsJsonObject();
    } catch (IOException error) {
      throw new IllegalArgumentException("Invalid request JSON: " + error.getMessage(), error);
    }
  }

  private static JsonElement readRequestValue(JsonReader reader) throws IOException {
    switch (reader.peek()) {
      case BEGIN_OBJECT:
        JsonObject object = new JsonObject();
        reader.beginObject();
        while (reader.hasNext()) {
          String name = reader.nextName();
          validateRequestString(name);
          if (object.has(name)) {
            throw new IllegalArgumentException("Duplicate request member: " + name);
          }
          object.add(name, readRequestValue(reader));
        }
        reader.endObject();
        return object;
      case BEGIN_ARRAY:
        JsonArray array = new JsonArray();
        reader.beginArray();
        while (reader.hasNext()) array.add(readRequestValue(reader));
        reader.endArray();
        return array;
      case STRING:
        String value = reader.nextString();
        validateRequestString(value);
        return new JsonPrimitive(value);
      case NUMBER:
        // Keep the original numeric precision and spelling without narrowing.
        return JsonParser.parseString(reader.nextString());
      case BOOLEAN:
        return new JsonPrimitive(reader.nextBoolean());
      case NULL:
        reader.nextNull();
        return JsonNull.INSTANCE;
      default:
        throw new IllegalArgumentException("Invalid request JSON value");
    }
  }

  /** An unpaired escaped surrogate cannot round-trip through the UTF-8 wire. */
  private static void validateRequestString(String value) {
    for (int i = 0; i < value.length(); i++) {
      char ch = value.charAt(i);
      if (Character.isHighSurrogate(ch)) {
        if (++i < value.length() && Character.isLowSurrogate(value.charAt(i))) continue;
      } else if (!Character.isLowSurrogate(ch)) {
        continue;
      }
      throw new IllegalArgumentException("Unpaired surrogate in request JSON string");
    }
  }

  /** Older Gson's non-lenient mode still accepts these non-JSON spellings. */
  private static void validateRequestTokens(String line) {
    boolean quoted = false;
    for (int i = 0; i < line.length(); i++) {
      char ch = line.charAt(i);
      if (quoted) {
        if (ch == '"') {
          quoted = false;
        } else if (ch == '\\') {
          if (++i == line.length() || "\"\\/bfnrtu".indexOf(line.charAt(i)) < 0) {
            throw new IllegalArgumentException("Invalid request JSON string escape");
          }
        } else if (ch < 0x20) {
          throw new IllegalArgumentException("Unescaped control character in request JSON string");
        }
      } else if (ch == '"') {
        quoted = true;
      } else if ("tTfFnN".indexOf(ch) >= 0) {
        String literal =
            ch == 't' || ch == 'T' ? "true" : ch == 'f' || ch == 'F' ? "false" : "null";
        if (line.regionMatches(true, i, literal, 0, literal.length())) {
          if (!line.startsWith(literal, i)) {
            throw new IllegalArgumentException("Invalid request JSON literal");
          }
          i += literal.length() - 1;
        }
      }
    }
  }

  /** A validation failure with diagnostics that survive handler boundaries. */
  public static class CommandException extends IllegalArgumentException {
    private final JsonObject detail;

    public CommandException(String message, JsonObject detail) {
      super(message);
      this.detail = detail;
    }

    JsonObject detail() {
      return detail;
    }
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
    resp.addProperty("message", message == null || message.isEmpty() ? "Command failed" : message);
    if (detail != null) {
      resp.add("detail", detail);
    }
    return resp;
  }

  public static JsonObject errorResult(String message) {
    JsonObject result = new JsonObject();
    result.addProperty("error", message == null || message.isEmpty() ? "Command failed" : message);
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

  public static String errorMessage(Throwable cause) {
    String message = cause.getMessage();
    return message == null || message.isEmpty() ? cause.toString() : message;
  }

  /** VM failures and forced thread termination cannot be safely returned as job errors. */
  public static boolean isFatalError(Error error) {
    return error instanceof VirtualMachineError || error instanceof ThreadDeath;
  }

  public static String getArgString(JsonObject args, String key) {
    if (args == null || !args.has(key) || args.get(key).isJsonNull()) return null;
    JsonElement value = args.get(key);
    if (!value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString()) {
      throw new IllegalArgumentException(key + " must be a string");
    }
    return value.getAsString();
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
    JsonElement value = args.get(key);
    if (!value.isJsonPrimitive() || !value.getAsJsonPrimitive().isBoolean()) {
      throw new IllegalArgumentException(key + " must be a boolean");
    }
    return value.getAsBoolean();
  }

  public static String[] getArgStringArray(JsonObject args, String key) {
    if (args == null || !args.has(key) || args.get(key).isJsonNull()) return new String[0];
    if (!args.get(key).isJsonArray()) {
      throw new IllegalArgumentException(key + " must be an array of strings");
    }
    JsonArray arr = args.getAsJsonArray(key);
    String[] out = new String[arr.size()];
    for (int i = 0; i < arr.size(); i++) {
      JsonElement value = arr.get(i);
      if (!value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString()) {
        throw new IllegalArgumentException(key + " must be an array of strings");
      }
      out[i] = value.getAsString();
    }
    return out;
  }

  public static JsonArray toJsonArray(String[] values) {
    JsonArray arr = new JsonArray();
    for (String v : values) arr.add(v);
    return arr;
  }
}
