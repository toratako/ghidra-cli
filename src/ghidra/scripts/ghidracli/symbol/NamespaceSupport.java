package ghidracli.symbol;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidracli.protocol.JsonProtocol;
import ghidracli.session.ProgramSession;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.HashMap;
import java.util.Map;

/** Exact, global-rooted paths for the local namespace/class hierarchy. */
final class NamespaceSupport {
    private final ProgramSession session;

    NamespaceSupport(ProgramSession session) {
        this.session = session;
    }

    static void validateName(String name) throws InvalidInputException {
        SymbolUtilities.validateName(name);
    }

    static boolean isSupported(Namespace namespace) {
        if (namespace == null || namespace.isGlobal() || namespace.isExternal()) return false;
        SymbolType type = namespace.getSymbol().getSymbolType();
        return type == SymbolType.NAMESPACE || type == SymbolType.CLASS;
    }

    List<Namespace> all() throws CancelledException {
        List<Namespace> found = new ArrayList<>();
        ArrayDeque<Namespace> pending = new ArrayDeque<>();
        pending.add(session.program().getGlobalNamespace());
        while (!pending.isEmpty()) {
            SymbolIterator children = session.program().getSymbolTable().getSymbols(pending.remove());
            while (children.hasNext()) {
                session.monitor().checkCancelled();
                Symbol child = children.next();
                if (child.getSymbolType() != SymbolType.NAMESPACE
                        && child.getSymbolType() != SymbolType.CLASS) continue;
                Namespace namespace = (Namespace) child.getObject();
                if (!isSupported(namespace)) continue;
                found.add(namespace);
                pending.add(namespace);
            }
        }
        return found;
    }

    private List<Namespace> matchingPath(String path) throws CancelledException {
        List<Namespace> matches = new ArrayList<>();
        // Native names may themselves contain :: (including template arguments).
        // A displayed full path does not encode those component boundaries.
        for (Namespace namespace : all()) {
            if (namespace.getName(true).equals(path)) matches.add(namespace);
        }
        return matches;
    }

    Namespace resolve(String path) throws CancelledException {
        if (path == null || path.isEmpty()) {
            throw new IllegalArgumentException("Namespace path is required");
        }
        List<Namespace> matches = matchingPath(path);
        if (matches.isEmpty()) {
            throw new IllegalArgumentException("Local namespace or class not found: " + path);
        }
        if (matches.size() > 1) throw ambiguousPath(path, matches);
        return matches.get(0);
    }

    Namespace resolveSnapshot(JsonObject args, String key) throws CancelledException {
        JsonElement value = args.get(key);
        if (value == null || !value.isJsonObject()) {
            throw new IllegalArgumentException(key + " must be a namespace snapshot");
        }
        JsonObject expected = value.getAsJsonObject();
        if (!expected.has("id")) throw new IllegalArgumentException("Namespace target ID required");
        long id = Long.parseLong(expected.get("id").getAsString());
        Symbol symbol = session.program().getSymbolTable().getSymbol(id);
        Namespace namespace = symbol != null && symbol.getObject() instanceof Namespace
            ? (Namespace) symbol.getObject() : null;
        if (!isSupported(namespace) || !toJson(namespace).equals(expected)) {
            throw new IllegalArgumentException("Stale or invalid namespace target: " + id);
        }
        // The namespace commands own the local hierarchy rooted at Global, not
        // function-local or external namespace trees omitted by namespace list.
        for (Namespace parent = namespace.getParentNamespace(); !parent.isGlobal();
                parent = parent.getParentNamespace()) {
            if (!isSupported(parent)) {
                throw new IllegalArgumentException("Unsupported namespace hierarchy: " + id);
            }
        }
        session.monitor().checkCancelled();
        return namespace;
    }

    /** Check actual component ancestry; displayed names may themselves contain ::. */
    static boolean within(Namespace namespace, Namespace root) {
        for (Namespace current = namespace; current != null && !current.isGlobal();
                current = current.getParentNamespace()) {
            if (current.getID() == root.getID()) return true;
        }
        return false;
    }

    void checkRelocation(Namespace target, Namespace parent, String name)
            throws CancelledException {
        if (within(parent, target)) {
            throw new IllegalArgumentException("Cannot move a namespace into itself or a descendant");
        }
        SymbolIterator siblings = session.program().getSymbolTable().getSymbols(parent);
        while (siblings.hasNext()) {
            session.monitor().checkCancelled();
            Symbol sibling = siblings.next();
            if (sibling.getID() != target.getID() && sibling.getName().equals(name)) {
                throw new IllegalArgumentException("Destination already contains a symbol named " + name);
            }
        }
        String rootPath = parent.isGlobal() ? name : parent.getName(true) + "::" + name;
        Map<String, Namespace> paths = new HashMap<>();
        for (Namespace namespace : all()) {
            session.monitor().checkCancelled();
            boolean affected = within(namespace, target);
            String path = affected ? relocatedPath(namespace, target, rootPath) : namespace.getName(true);
            Namespace previous = paths.putIfAbsent(path, namespace);
            if (previous != null && (affected || within(previous, target))
                    && !previous.getName(true).equals(namespace.getName(true))) {
                throw ambiguousPath(path, List.of(previous, namespace));
            }
        }
    }

    private static String relocatedPath(Namespace namespace, Namespace target, String rootPath) {
        ArrayDeque<String> suffix = new ArrayDeque<>();
        for (Namespace current = namespace; current.getID() != target.getID();
                current = current.getParentNamespace()) suffix.addFirst(current.getName());
        return suffix.isEmpty() ? rootPath : rootPath + "::" + String.join("::", suffix);
    }

    void checkCreationPath(Namespace parent, String name, Namespace existing)
            throws CancelledException {
        String path = parent.isGlobal() ? name : parent.getName(true) + "::" + name;
        List<Namespace> matches = matchingPath(path);
        for (Namespace match : matches) {
            if (existing == null || match.getID() != existing.getID()) {
                throw ambiguousPath(path, matches);
            }
        }
    }

    private JsonProtocol.CommandException ambiguousPath(String path, List<Namespace> matches) {
        JsonArray candidates = new JsonArray();
        for (Namespace namespace : matches) candidates.add(toJson(namespace));
        JsonObject detail = new JsonObject();
        detail.addProperty("path", path);
        detail.add("candidates", candidates);
        return new JsonProtocol.CommandException("Ambiguous namespace path: " + path
            + "; use namespace rename PATH NEW_NAME --where \"id='ID'\" to disambiguate", detail);
    }

    static JsonObject toJson(Namespace namespace) {
        JsonObject result = new JsonObject();
        result.addProperty("id", Long.toString(namespace.getID()));
        result.addProperty("name", namespace.getName());
        result.addProperty("path", namespace.getName(true));
        Namespace parent = namespace.getParentNamespace();
        result.add("parent", parent.isGlobal() ? JsonNull.INSTANCE
            : new com.google.gson.JsonPrimitive(parent.getName(true)));
        result.addProperty("kind", namespace.getSymbol().getSymbolType() == SymbolType.CLASS
            ? "class" : "namespace");
        return result;
    }
}
