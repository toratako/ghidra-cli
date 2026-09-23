package ghidracli.types;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import ghidra.app.util.cparser.C.CParser;
import ghidra.app.util.cparser.C.CParserConstants;
import ghidra.app.util.cparser.C.Token;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StandAloneDataTypeManager;
import ghidracli.protocol.JsonProtocol;
import ghidracli.session.ProgramSession;
import java.io.StringReader;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Isolated C parser types with the same unambiguous lookup as --type edits. */
public final class SignatureTypes extends StandAloneDataTypeManager {
    private final TypeResolver resolver;
    private final Map<String, DataType> bindings = new HashMap<>();
    private final Map<String, DataType> resolved = new HashMap<>();
    private final Set<String> missing = new HashSet<>();
    private CParser parser;

    public SignatureTypes(ProgramSession session) {
        super("Function signature", session.program().getDataTypeManager().getDataOrganization());
        resolver = new TypeResolver(session);
    }

    public void bind(JsonElement value) {
        if (value == null || value.isJsonNull()) return;
        if (!value.isJsonArray()) {
            throw new IllegalArgumentException("type_bindings must be an array of {name, path}");
        }
        for (JsonElement item : value.getAsJsonArray()) {
            if (!item.isJsonObject()) {
                throw new IllegalArgumentException("Each type binding must contain name and path strings");
            }
            JsonObject binding = item.getAsJsonObject();
            String name = string(binding, "name");
            String path = string(binding, "path");
            if (!name.matches("[A-Za-z_][A-Za-z_0-9]*") || name.equals("_Atomic")
                    || new CParser(new StringReader(name)).getNextToken().kind != CParserConstants.IDENTIFIER) {
                throw new IllegalArgumentException("Type binding name must be a non-keyword C identifier: " + name);
            }
            if (!path.startsWith("/") || path.endsWith("/")) {
                throw new IllegalArgumentException("Type binding path must be an absolute datatype path: " + path);
            }
            if (bindings.containsKey(name)) {
                throw new IllegalArgumentException("Duplicate type binding: " + name);
            }
            DataType type = resolver.resolveDataTypePath(path);
            if (type == null) throw unknown(path);
            bindings.put(name, type.clone(this));
        }
    }

    private static String string(JsonObject binding, String key) {
        JsonElement value = binding.get(key);
        if (value == null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString()) {
            throw new IllegalArgumentException("Type binding " + key + " must be a string");
        }
        return value.getAsString();
    }

    /** CParser's native lookup picks its first match; provide at most one. */
    @Override
    public void findDataTypes(String name, List<DataType> results) {
        Token previous = parser.getToken(0);
        Token next = parser.getToken(1);
        // The grammar also probes the parameter name after a named type.
        // That identifier is not another type, even if the Program has matches.
        if (previous.kind == CParserConstants.IDENTIFIER && name.equals(next.image)
                && !name.equals(previous.image)) return;
        DataType type = lookup(name);
        if (type != null) results.add(type);
        else if (next.kind == CParserConstants.IDENTIFIER && name.equals(next.image)
                && ("(".equals(previous.image) || ",".equals(previous.image))) {
            // Otherwise CParser treats an unknown type as a K&R parameter name
            // and silently supplies the undefined datatype.
            throw unknown(name);
        }
    }

    public void attach(CParser parser) {
        this.parser = parser;
    }

    public DataType lookup(String name) {
        if (bindings.containsKey(name)) return bindings.get(name);
        if (resolved.containsKey(name)) return resolved.get(name);
        if (missing.contains(name)) return null;
        DataType type;
        try {
            type = resolver.resolveDataType(name);
        } catch (TypeResolver.TypeResolutionException e) {
            JsonObject detail = JsonProtocol.errorDetail(e);
            throw new JsonProtocol.CommandException("Ambiguous type name '" + name
                + "'. Use --bind-type " + name + " PATH to select one of " + detail.get("candidates"), detail);
        }
        if (type == null) {
            missing.add(name);
            return null;
        }
        type = type.clone(this);
        resolved.put(name, type);
        return type;
    }

    public boolean wasMissing(String name) {
        return missing.contains(name);
    }

    public static JsonProtocol.CommandException unknown(String name) {
        JsonObject detail = new JsonObject();
        detail.addProperty("type_name", name);
        return new JsonProtocol.CommandException("Type not found: " + name, detail);
    }
}
