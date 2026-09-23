package ghidracli.symbol;

import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.CancelledException;
import ghidracli.function.FunctionQueries;
import ghidracli.protocol.JsonProtocol;
import ghidracli.query.AddressCodec;
import ghidracli.query.AddressResolver;
import ghidracli.session.ProgramSession;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static ghidracli.protocol.JsonProtocol.errorResult;
import static ghidracli.protocol.JsonProtocol.getArgString;

public final class NamespaceCommands {
    private final ProgramSession session;
    private final NamespaceSupport namespaces;

    public NamespaceCommands(ProgramSession session) {
        this.session = session;
        namespaces = new NamespaceSupport(session);
    }

    public JsonObject handleList(JsonObject args) throws ghidra.util.exception.CancelledException {
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

    public JsonObject handleGet(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");
        try {
            return NamespaceSupport.toJson(namespaces.resolve(getArgString(args, "path")));
        } catch (Exception e) {
            return errorResult("Failed to get namespace: " + e.getMessage(), e);
        }
    }

    public JsonObject handleCreate(JsonObject args) {
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

    public JsonObject handleRename(JsonObject args) {
        return relocate(args, false);
    }

    public JsonObject handleMove(JsonObject args) {
        return relocate(args, true);
    }

    private JsonObject relocate(JsonObject args, boolean move) {
        if (session.program() == null) return errorResult("No program loaded");
        try {
            Namespace target = namespaces.resolveSnapshot(args, "target");
            Namespace parent = target.getParentNamespace();
            String name = target.getName();
            if (move) {
                if (!args.has("parent")) {
                    throw new IllegalArgumentException("Namespace parent snapshot or explicit null required");
                }
                parent = args.get("parent").isJsonNull() ? session.program().getGlobalNamespace()
                    : namespaces.resolveSnapshot(args, "parent");
            } else {
                name = getArgString(args, "new_name");
                NamespaceSupport.validateName(name);
            }
            JsonObject before = NamespaceSupport.toJson(target);
            boolean changed = !target.getName().equals(name)
                || target.getParentNamespace().getID() != parent.getID();
            JsonArray functionChanges = new JsonArray();
            if (changed) {
                namespaces.checkRelocation(target, parent, name);
                List<Symbol> members = subtree(target);
                Map<Long, JsonObject> functionsBefore = functionSnapshots(members);
                Set<Long> ids = new HashSet<>();
                for (Symbol member : members) ids.add(member.getID());
                if (move) target.getSymbol().setNamespace(parent);
                else target.getSymbol().setName(name, SourceType.USER_DEFINED);
                session.monitor().checkCancelled();
                SymbolTable table = session.program().getSymbolTable();
                for (long id : ids) {
                    session.monitor().checkCancelled();
                    Symbol preserved = table.getSymbol(id);
                    if (preserved == null || preserved.isDeleted()) {
                        throw new IllegalStateException("Ghidra did not preserve descendant symbol ID " + id);
                    }
                }
                for (Map.Entry<Long, JsonObject> entry : functionsBefore.entrySet()) {
                    session.monitor().checkCancelled();
                    Function function = session.program().getFunctionManager().getFunction(entry.getKey());
                    if (function == null) throw new IllegalStateException("Ghidra removed a descendant function");
                    JsonObject after = functionSnapshot(function);
                    if (!entry.getValue().equals(after)) {
                        JsonObject change = new JsonObject();
                        change.addProperty("id", Long.toString(entry.getKey()));
                        change.addProperty("address", AddressCodec.format(function.getEntryPoint()));
                        change.add("before", entry.getValue());
                        change.add("after", after);
                        functionChanges.add(change);
                    }
                }
            }
            if (target.getSymbol().isDeleted() || !target.getName().equals(name)
                    || target.getParentNamespace().getID() != parent.getID()
                    || !Long.toString(target.getID()).equals(before.get("id").getAsString())) {
                throw new IllegalStateException("Ghidra did not retain the requested namespace identity and path");
            }
            JsonObject result = new JsonObject();
            result.addProperty("status", changed ? (move ? "moved" : "renamed") : "unchanged");
            result.add("before", before);
            result.add("after", NamespaceSupport.toJson(target));
            result.add("function_changes", functionChanges);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to " + (move ? "move" : "rename") + " namespace: " + e.getMessage(), e);
        }
    }

    public JsonObject handleDelete(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");
        try {
            Namespace target = namespaces.resolveSnapshot(args, "target");
            boolean recursive = JsonProtocol.getArgBool(args, "recursive", false);
            JsonObject selected = NamespaceSupport.toJson(target);
            List<Symbol> members = subtree(target);
            if (!recursive && members.size() != 1) {
                JsonObject detail = new JsonObject();
                detail.add("target", selected);
                detail.addProperty("descendant_count", members.size() - 1);
                throw new JsonProtocol.CommandException(
                    "Namespace is not empty; use --recursive to delete its descendants", detail);
            }
            checkOutsideThunks(members);
            JsonArray deleted = new JsonArray();
            JsonObject counts = new JsonObject();
            Set<Long> functionIds = new HashSet<>();
            Set<Long> namespaceIds = new HashSet<>();
            for (Symbol member : members) {
                session.monitor().checkCancelled();
                deleted.add(deletionSnapshot(member));
                String type = member.getSymbolType().toString();
                counts.addProperty(type, counts.has(type) ? counts.get(type).getAsInt() + 1 : 1);
                if (member.getSymbolType() == SymbolType.FUNCTION) functionIds.add(member.getID());
                if (member.getSymbolType().isNamespace()) namespaceIds.add(member.getID());
            }
            // Native parent deletion suppresses recreation of child function labels.
            // Its child deletes can return false even after successful removal, so
            // verify every recorded identity rather than trusting the cascade.
            if (!target.getSymbol().delete()) throw new IllegalStateException("Ghidra refused to delete namespace");
            SymbolTable table = session.program().getSymbolTable();
            for (var element : deleted) {
                session.monitor().checkCancelled();
                long id = Long.parseLong(element.getAsJsonObject().get("id").getAsString());
                Symbol remaining = table.getSymbol(id);
                if (remaining != null && !remaining.isDeleted()) {
                    throw new IllegalStateException("Ghidra did not delete descendant symbol " + id);
                }
                if (functionIds.contains(id) && session.program().getFunctionManager().getFunction(id) != null) {
                    throw new IllegalStateException("Ghidra did not delete descendant function " + id);
                }
                // Cascading function/thunk deletion may recreate labels. An ID
                // check alone would miss a new symbol left under a deleted parent.
                if (namespaceIds.contains(id) && table.getSymbols(id).hasNext()) {
                    throw new IllegalStateException("Ghidra left symbols under deleted namespace " + id);
                }
            }
            JsonObject result = new JsonObject();
            result.addProperty("status", "deleted");
            result.add("target", selected);
            result.addProperty("recursive", recursive);
            result.addProperty("count", deleted.size());
            result.add("counts", counts);
            result.add("deleted", deleted);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to delete namespace: " + e.getMessage(), e);
        }
    }

    private List<Symbol> subtree(Namespace root) throws CancelledException {
        List<Symbol> found = new ArrayList<>();
        ArrayDeque<Symbol> pending = new ArrayDeque<>();
        pending.add(root.getSymbol());
        while (!pending.isEmpty()) {
            session.monitor().checkCancelled();
            Symbol symbol = pending.remove();
            found.add(symbol);
            // Functions are also namespaces: their parameters/local variables are
            // real deletion effects even though namespace list excludes functions.
            if (symbol.getObject() instanceof Namespace) {
                SymbolIterator children = session.program().getSymbolTable().getSymbols((Namespace) symbol.getObject());
                while (children.hasNext()) {
                    session.monitor().checkCancelled();
                    pending.add(children.next());
                }
            }
        }
        return found;
    }

    private void checkOutsideThunks(List<Symbol> members) throws CancelledException {
        Set<Long> ids = new HashSet<>();
        for (Symbol member : members) ids.add(member.getID());
        for (Symbol member : members) {
            session.monitor().checkCancelled();
            if (member.getSymbolType() != SymbolType.FUNCTION) continue;
            Function function = (Function) member.getObject();
            Address[] thunks = function.getFunctionThunkAddresses(true);
            if (thunks == null) continue;
            for (Address address : thunks) {
                session.monitor().checkCancelled();
                Function thunk = session.program().getFunctionManager().getFunctionAt(address);
                if (thunk != null && !ids.contains(thunk.getID())) {
                    JsonObject detail = new JsonObject();
                    detail.add("function", deletionSnapshot(member));
                    detail.add("outside_thunk", deletionSnapshot(thunk.getSymbol()));
                    throw new JsonProtocol.CommandException(
                        "Deleting this namespace would delete a thunk outside its subtree; clear or move that thunk first", detail);
                }
            }
        }
    }

    private JsonObject deletionSnapshot(Symbol symbol) {
        JsonObject row = new JsonObject();
        row.addProperty("id", Long.toString(symbol.getID()));
        row.addProperty("name", symbol.getName());
        row.addProperty("path", symbol.getName(true));
        Namespace parent = symbol.getParentNamespace();
        row.add("parent", parent.isGlobal() ? JsonNull.INSTANCE
            : new com.google.gson.JsonPrimitive(parent.getName(true)));
        row.addProperty("type", symbol.getSymbolType().toString());
        row.addProperty("address", AddressCodec.format(symbol.getAddress()));
        return row;
    }

    private Map<Long, JsonObject> functionSnapshots(List<Symbol> members) throws CancelledException {
        Map<Long, JsonObject> found = new LinkedHashMap<>();
        for (Symbol member : members) {
            session.monitor().checkCancelled();
            if (member.getSymbolType() == SymbolType.FUNCTION) {
                Function function = (Function) member.getObject();
                if (!found.containsKey(member.getID())) found.put(member.getID(), functionSnapshot(function));
                // Thunks outside the stored hierarchy can inherit the target's
                // signature and (for default names) its effective class namespace.
                Address[] thunks = function.getFunctionThunkAddresses(true);
                if (thunks == null) continue;
                for (Address address : thunks) {
                    session.monitor().checkCancelled();
                    Function thunk = session.program().getFunctionManager().getFunctionAt(address);
                    if (thunk != null && !found.containsKey(thunk.getID())) {
                        found.put(thunk.getID(), functionSnapshot(thunk));
                    }
                }
            }
        }
        return found;
    }

    private JsonObject functionSnapshot(Function function) throws CancelledException {
        FunctionQueries queries = new FunctionQueries(session, new AddressResolver(session));
        JsonObject result = queries.signatureDetailsToJson(function);
        result.addProperty("signature", function.getPrototypeString(false, false));
        result.addProperty("calling_convention", function.getCallingConventionName());
        return result;
    }
}
