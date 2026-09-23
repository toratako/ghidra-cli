package ghidracli.analysis;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidracli.query.AddressCodec;
import ghidracli.query.IntegerLiteral;
import ghidracli.session.ProgramSession;
import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Locale;

import static ghidracli.protocol.JsonProtocol.errorResult;

public final class AnalysisCommands {
    private final ProgramSession session;

    public AnalysisCommands(ProgramSession session) {
        this.session = session;
    }

    public JsonObject handleRun(JsonObject args) throws Exception {
        boolean hasStart = args != null && args.has("start");
        boolean hasEnd = args != null && args.has("end");
        boolean pending = false;
        if (args != null && args.has("pending")) {
            JsonElement value = args.get("pending");
            if (!value.isJsonPrimitive() || !value.getAsJsonPrimitive().isBoolean()) {
                throw new IllegalArgumentException("pending must be a boolean");
            }
            pending = value.getAsBoolean();
        }
        if (hasStart != hasEnd) {
            throw new IllegalArgumentException("start and end must be specified together");
        }
        if (pending && hasStart) {
            throw new IllegalArgumentException("pending cannot be combined with start/end");
        }
        String startText = hasStart ? requireString(args, "start") : null;
        String endText = hasEnd ? requireString(args, "end") : null;
        if (hasStart && (!AddressCodec.isValidSyntax(startText)
                || !AddressCodec.isValidSyntax(endText))) {
            throw new IllegalArgumentException("start and end must be explicit addresses");
        }
        if (args != null && args.has("program")) {
            String name = requireString(args, "program");
            if (name.isEmpty()) throw new IllegalArgumentException("Program name required");
            session.open(session.findProgram(name));
        }
        if (session.program() == null) return errorResult("No program loaded");

        AddressSet range = null;
        JsonObject receipt = new JsonObject();
        receipt.addProperty("mode", pending ? "pending" : hasStart ? "range" : "full");
        receipt.addProperty("program", session.programName());
        if (hasStart) {
            Address start = AddressCodec.parse(session.program().getAddressFactory(), startText);
            Address end = AddressCodec.parse(session.program().getAddressFactory(), endText);
            if (!start.getAddressSpace().equals(end.getAddressSpace())) {
                throw new IllegalArgumentException("start and end must use the same address space");
            }
            if (start.compareTo(end) > 0) {
                throw new IllegalArgumentException("start must not exceed end");
            }
            range = new AddressSet(start, end).intersect(session.program().getMemory());
            if (range.isEmpty()) {
                throw new IllegalArgumentException("Analysis range contains no program memory");
            }
            receipt.addProperty("start", AddressCodec.format(start));
            receipt.addProperty("end", AddressCodec.format(end));
        }
        try {
            if (pending) session.analyzePending();
            else if (range != null) session.analyzeRange(range);
            else session.analyzeAll();
            receipt.addProperty("status", "success");
            receipt.addProperty("completed", true);
            receipt.addProperty("function_count", session.program().getFunctionManager().getFunctionCount());
            return receipt;
        } catch (Exception failure) {
            receipt.addProperty("completed", false);
            if (failure instanceof CancelledException || session.monitor().isCancelled()) {
                receipt.addProperty("cancelled", true);
            }
            JsonObject result = errorResult("Analysis failed: " + failure.getMessage());
            result.add("detail", receipt);
            return result;
        }
    }

    public JsonObject handleOptionList(JsonObject args) throws Exception {
        if (session.program() == null) return errorResult("No program loaded");
        Options options = session.program().getOptions(Program.ANALYSIS_PROPERTIES);
        var names = new ArrayList<>(options.getOptionNames());
        Collections.sort(names);
        JsonArray rows = new JsonArray();
        for (String name : names) {
            session.monitor().checkCancelled();
            rows.add(describe(options, name));
        }
        JsonObject result = new JsonObject();
        result.addProperty("count", rows.size());
        result.add("options", rows);
        return result;
    }

    public JsonObject handleOptionGet(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");
        Options options = session.program().getOptions(Program.ANALYSIS_PROPERTIES);
        return describe(options, requireName(options, args));
    }

    public JsonObject handleOptionSet(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");
        Options options = session.program().getOptions(Program.ANALYSIS_PROPERTIES);
        String name = requireName(options, args);
        String text = requireString(args, "value");
        OptionType type = options.getType(name);
        Object value;
        try {
            value = parseValue(type, text, enumValues(options, name));
        } catch (IllegalArgumentException | ArithmeticException error) {
            throw new IllegalArgumentException("Invalid value for analysis option '" + name
                + "' (" + typeName(type) + "): " + error.getMessage());
        }
        // Parse and validate before touching the Program. The session owns commit/save.
        options.putObject(name, value);
        JsonObject result = describe(options, name);
        result.addProperty("status", "set");
        return result;
    }

    private static String requireString(JsonObject args, String key) {
        JsonElement value = args == null ? null : args.get(key);
        if (value == null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString()) {
            throw new IllegalArgumentException(key + " must be a string");
        }
        return value.getAsString();
    }

    private static String requireName(Options options, JsonObject args) {
        String name = requireString(args, "name");
        if (name.isEmpty() || !options.getOptionNames().contains(name)) {
            throw new IllegalArgumentException("Unknown analysis option: " + name);
        }
        return name;
    }

    private static String typeName(OptionType type) {
        return type.name().replace("_TYPE", "").toLowerCase(Locale.ROOT);
    }

    private static Enum<?>[] enumValues(Options options, String name) {
        if (options.getType(name) != OptionType.ENUM_TYPE) return new Enum<?>[0];
        Object value = options.getObject(name, options.getDefaultValue(name));
        if (!(value instanceof Enum<?>)) value = options.getDefaultValue(name);
        return value instanceof Enum<?> e ? e.getDeclaringClass().getEnumConstants() : new Enum<?>[0];
    }

    private static JsonObject describe(Options options, String name) {
        OptionType type = options.getType(name);
        Object defaultValue = options.getDefaultValue(name);
        Enum<?>[] enums = enumValues(options, name);
        JsonObject result = new JsonObject();
        result.addProperty("name", name);
        result.addProperty("type", typeName(type));
        result.add("value", jsonValue(type, options.getObject(name, defaultValue)));
        result.add("default", jsonValue(type, defaultValue));
        result.addProperty("description", options.getDescription(name));
        result.addProperty("settable", switch (type) {
            case BOOLEAN_TYPE, INT_TYPE, LONG_TYPE, FLOAT_TYPE, DOUBLE_TYPE,
                 STRING_TYPE, FILE_TYPE -> true;
            case ENUM_TYPE -> enums.length != 0;
            default -> false;
        });
        if (type == OptionType.ENUM_TYPE) {
            JsonArray choices = new JsonArray();
            for (Enum<?> value : enums) choices.add(value.name());
            result.add("choices", choices);
        }
        return result;
    }

    private static JsonElement jsonValue(OptionType type, Object value) {
        if (value == null) return JsonNull.INSTANCE;
        if (value instanceof Boolean b) return new JsonPrimitive(b);
        if (value instanceof Number n) return new JsonPrimitive(n);
        if (value instanceof String s) return new JsonPrimitive(s);
        if (value instanceof Enum<?> e) return new JsonPrimitive(e.name());
        if (value instanceof File f) return new JsonPrimitive(f.getPath());
        return new JsonPrimitive(type.convertObjectToString(value));
    }

    private static Object parseValue(OptionType type, String text, Enum<?>[] enums) {
        return switch (type) {
            case BOOLEAN_TYPE -> {
                if (!text.equalsIgnoreCase("true") && !text.equalsIgnoreCase("false")) {
                    throw new IllegalArgumentException("expected true or false");
                }
                yield Boolean.valueOf(text);
            }
            case INT_TYPE -> IntegerLiteral.parse(text).intValueExact();
            case LONG_TYPE -> IntegerLiteral.parse(text).longValueExact();
            case FLOAT_TYPE -> {
                float value = Float.parseFloat(text);
                if (!Float.isFinite(value)) throw new IllegalArgumentException("expected a finite float");
                yield value;
            }
            case DOUBLE_TYPE -> {
                double value = Double.parseDouble(text);
                if (!Double.isFinite(value)) throw new IllegalArgumentException("expected a finite double");
                yield value;
            }
            case STRING_TYPE -> text;
            case FILE_TYPE -> {
                File value = new File(text);
                // The persistent JVM may have a different working directory than the caller.
                if (!value.isAbsolute()) throw new IllegalArgumentException("expected an absolute file path");
                yield value;
            }
            case ENUM_TYPE -> {
                Enum<?> selected = null;
                for (Enum<?> value : enums) {
                    if (value.name().equals(text)) selected = value;
                }
                if (selected == null) throw new IllegalArgumentException("expected an enum name from choices");
                yield selected;
            }
            default -> throw new IllegalArgumentException("this option type cannot be set through the CLI");
        };
    }
}
