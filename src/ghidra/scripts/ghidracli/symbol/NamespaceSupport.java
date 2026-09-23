package ghidracli.symbol;

import com.google.gson.JsonArray;
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
            + "; rename a namespace with symbol rename and an ID filter to disambiguate", detail);
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
