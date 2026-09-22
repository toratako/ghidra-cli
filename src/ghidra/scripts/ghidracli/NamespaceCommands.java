package ghidracli;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import java.util.Comparator;
import java.util.List;
import static ghidracli.JsonProtocol.errorResult;
import static ghidracli.JsonProtocol.getArgString;

final class NamespaceCommands {
    private final ProgramSession session;
    private final NamespaceSupport namespaces;

    NamespaceCommands(ProgramSession session) {
        this.session = session;
        namespaces = new NamespaceSupport(session);
    }

    JsonObject handleList(JsonObject args) throws ghidra.util.exception.CancelledException {
        if (session.program() == null) return errorResult("No program loaded");
        List<Namespace> found = namespaces.all();
        found.sort(Comparator.comparing(namespace -> namespace.getName(true)));
        JsonArray rows = new JsonArray();
        for (Namespace namespace : found) rows.add(NamespaceSupport.toJson(namespace));
        JsonObject result = new JsonObject();
        result.add("namespaces", rows);
        result.addProperty("count", rows.size());
        return result;
    }

    JsonObject handleGet(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");
        try {
            return NamespaceSupport.toJson(namespaces.resolve(getArgString(args, "path")));
        } catch (Exception e) {
            return errorResult("Failed to get namespace: " + e.getMessage(), e);
        }
    }

    JsonObject handleCreate(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");
        try {
            String name = getArgString(args, "name");
            NamespaceSupport.validateName(name);
            String kind = getArgString(args, "kind");
            if (kind == null) kind = "namespace";
            if (!kind.equals("namespace") && !kind.equals("class")) {
                throw new IllegalArgumentException("Namespace kind must be namespace or class");
            }
            String parentPath = getArgString(args, "parent");
            Namespace parent = parentPath == null ? session.program().getGlobalNamespace()
                : namespaces.resolve(parentPath);
            SymbolTable table = session.program().getSymbolTable();
            Namespace existing = table.getNamespace(name, parent);
            namespaces.checkCreationPath(parent, name, existing);
            if (existing != null) {
                if (!NamespaceSupport.isSupported(existing)
                        || !NamespaceSupport.toJson(existing).get("kind").getAsString().equals(kind)) {
                    throw new IllegalArgumentException("Namespace name conflicts with a different kind: " + name);
                }
                JsonObject result = NamespaceSupport.toJson(existing);
                result.addProperty("status", "unchanged");
                return result;
            }
            Namespace created = kind.equals("class")
                ? table.createClass(parent, name, SourceType.USER_DEFINED)
                : table.createNameSpace(parent, name, SourceType.USER_DEFINED);
            JsonObject result = NamespaceSupport.toJson(created);
            result.addProperty("status", "created");
            return result;
        } catch (Exception e) {
            return errorResult("Failed to create namespace: " + e.getMessage(), e);
        }
    }
}
