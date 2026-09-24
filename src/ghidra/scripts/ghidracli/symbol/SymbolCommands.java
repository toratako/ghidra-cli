package ghidracli.symbol;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalManager;
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
import ghidracli.query.ListQuery;
import ghidracli.session.ProgramSession;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static ghidracli.protocol.JsonProtocol.errorResult;
import static ghidracli.protocol.JsonProtocol.getArgString;
import static ghidracli.protocol.JsonProtocol.getNonnegativeIntArg;

public final class SymbolCommands {
    private final ProgramSession session;

    public SymbolCommands(ProgramSession session) {
        this.session = session;
    }

    public JsonObject handleSymbolList(JsonObject args) throws ghidra.util.exception.CancelledException {
        if (session.program() == null) return errorResult("No program loaded");

        ListQuery query = new ListQuery(session, args);

        SymbolTable symbolTable = session.program().getSymbolTable();
        JsonArray symbols = new JsonArray();

        collectSymbols(symbolTable.getAllSymbols(true), query, symbols, false);
        if (!query.isFull()) {
            // The address iterator covers memory/external symbols (including dynamic
            // labels), but omits namespaces, classes, parameters and local variables.
            // Append those without collecting every symbol ID or changing address order.
            collectSymbols(symbolTable.getDefinedSymbols(), query, symbols, true);
        }

        JsonObject result = new JsonObject();
        result.add("symbols", symbols);
        result.addProperty("count", symbols.size());
        return result;
    }

    private void collectSymbols(SymbolIterator iterator, ListQuery query, JsonArray symbols,
            boolean outsideAddressIterator) throws CancelledException {
        while (!query.isFull() && iterator.hasNext()) {
            Symbol symbol = iterator.next();
            Address address = symbol.getAddress();
            if (outsideAddressIterator && (address.isMemoryAddress() || address.isExternalAddress())) {
                continue;
            }
            if (query.include(symbol.getName())) {
                symbols.add(symbolToJson(symbol));
                query.record();
            }
        }
    }

    public JsonObject handleSymbolGet(JsonObject args) throws CancelledException {
        return lookupSymbols(args, false);
    }

    public JsonObject handleSymbolGetByName(JsonObject args) throws CancelledException {
        return lookupSymbols(args, true);
    }

    private JsonObject lookupSymbols(JsonObject args, boolean nameOnly) throws CancelledException {
        if (session.program() == null) return errorResult("No program loaded");

        String addressOrName = getArgString(args, "name");
        if (addressOrName == null || addressOrName.isEmpty()) {
            return errorResult("No symbol name or address provided");
        }

        SymbolTable symbolTable = session.program().getSymbolTable();
        JsonArray syms = new JsonArray();
        boolean explicitAddress = AddressCodec.isExplicit(addressOrName);

        // Mutation candidates always use an exact name, including names such as
        // dead, 1234, or 0xdead. Public get reserves the explicit 0x/0X prefix.
        if (nameOnly || !explicitAddress) {
            for (Symbol symbol : symbolsNamed(symbolTable, addressOrName)) {
                syms.add(symbolToJson(symbol));
            }
        }

        if (!nameOnly && explicitAddress) {
            try {
                Address addr = new AddressResolver(session).parseAddress(addressOrName);
                if (addr == null) return errorResult("Invalid address: " + addressOrName);
                Symbol[] symbolsAtAddr = symbolTable.getSymbols(addr);
                if (symbolsAtAddr.length == 0) {
                    return errorResult("No symbol at address: " + addressOrName);
                }
                for (Symbol s : symbolsAtAddr) {
                    syms.add(symbolToJson(s));
                }
            } catch (Exception e) {
                return errorResult("Invalid address: " + addressOrName);
            }
        }

        if (syms.size() == 0) {
            return errorResult("Symbol not found: " + addressOrName);
        }

        JsonObject result = new JsonObject();
        result.add("symbols", syms);
        return result;
    }

    private List<Symbol> symbolsNamed(SymbolTable table, String name) throws CancelledException {
        // Preserve indexed namespace/variable matches, which the address iterator omits.
        // Then add displayed default thunks and dynamic labels missing from the name index.
        List<Symbol> matches = new ArrayList<>();
        Set<Long> ids = new HashSet<>();
        SymbolIterator indexed = table.getSymbols(name);
        while (indexed.hasNext()) {
            session.monitor().checkCancelled();
            Symbol symbol = indexed.next();
            if (symbol.getName().equals(name) && ids.add(symbol.getID())) matches.add(symbol);
        }
        SymbolIterator symbols = table.getAllSymbols(true);
        while (symbols.hasNext()) {
            session.monitor().checkCancelled();
            Symbol symbol = symbols.next();
            if (symbol.getName().equals(name) && ids.add(symbol.getID())) matches.add(symbol);
        }
        return matches;
    }

    public JsonObject handleSymbolCreateLabel(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String addressStr = getArgString(args, "address");
        String name = getArgString(args, "name");
        if (addressStr == null || name == null) {
            return errorResult("Address and name required");
        }

        try {
            Address addr = AddressCodec.parse(session.program().getAddressFactory(), addressStr);
            if (addr == null) return errorResult("Invalid address: " + addressStr);

            SymbolTable symbolTable = session.program().getSymbolTable();
            for (Symbol symbol : symbolTable.getSymbols(addr)) {
                if (symbol.getSymbolType() == SymbolType.FUNCTION
                        && symbol.getSource() == SourceType.DEFAULT) {
                    return errorResult("A default-named function exists at this address; "
                        + "use function rename to name it before creating a label");
                }
            }
            symbolTable.createLabel(addr, name, SourceType.USER_DEFINED);

            JsonObject result = new JsonObject();
            result.addProperty("status", "created");
            result.addProperty("address", AddressCodec.format(addr));
            result.addProperty("name", name);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to create symbol: " + e.getMessage());
        }
    }

    private JsonObject symbolToJson(Symbol symbol) {
        JsonObject result = new JsonObject();
        result.addProperty("id", Long.toString(symbol.getID()));
        result.addProperty("name", symbol.getName());
        result.addProperty("address", AddressCodec.format(symbol.getAddress()));
        result.addProperty("namespace", symbol.getParentNamespace().getName(true));
        result.addProperty("type", symbol.getSymbolType().toString());
        result.addProperty("source", symbol.getSource().toString());
        result.addProperty("is_primary", symbol.isPrimary());
        result.addProperty("address_space", symbol.getAddress().getAddressSpace().getName());
        result.addProperty("is_default_address_space", symbol.getAddress().getAddressSpace().equals(
            session.program().getAddressFactory().getDefaultAddressSpace()));
        return result;
    }

    /** Revalidate the entire selection before mutating any selected symbol. */
    private List<Symbol> resolveScopedSymbols(SymbolTable table, String name, JsonObject args)
            throws CancelledException {
        if (!args.has("targets") || !args.get("targets").isJsonArray()) {
            throw new IllegalArgumentException("Symbol targets must be an array");
        }
        JsonArray targets = args.getAsJsonArray("targets");
        if (targets.size() == 0) throw new IllegalArgumentException("Symbol targets cannot be empty");
        List<Symbol> selected = new ArrayList<>();
        Set<Long> ids = new HashSet<>();
        for (JsonElement element : targets) {
            JsonObject expected = element.getAsJsonObject();
            long id = Long.parseLong(expected.get("id").getAsString());
            Symbol symbol = table.getSymbol(id);
            if (!ids.add(id) || symbol == null || !symbol.getName().equals(name)
                    || !symbolToJson(symbol).equals(expected)) {
                throw new IllegalArgumentException("Stale or invalid symbol target: " + id);
            }
            selected.add(symbol);
        }
        return selected;
    }

    private Symbol resolveLocalTarget(JsonObject args, boolean labelOnly) throws CancelledException {
        String name = getArgString(args, "name");
        if (name == null || name.isEmpty()) throw new IllegalArgumentException("Symbol name required");
        List<Symbol> targets = resolveScopedSymbols(session.program().getSymbolTable(), name, args);
        if (targets.size() != 1) {
            throw new IllegalArgumentException("Exactly one symbol target is required");
        }
        Symbol symbol = targets.get(0);
        if (symbol.isDynamic() || symbol.isExternal() || !symbol.getAddress().isMemoryAddress()
                || (symbol.getSymbolType() != SymbolType.LABEL
                    && (labelOnly || symbol.getSymbolType() != SymbolType.FUNCTION))) {
            throw new IllegalArgumentException(labelOnly
                ? "Target must be a persisted local label"
                : "Target must be a persisted local label or function");
        }
        return symbol;
    }

    public JsonObject handleSetNamespace(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");
        try {
            Symbol symbol = resolveLocalTarget(args, false);
            String path = getArgString(args, "namespace");
            boolean global = JsonProtocol.getArgBool(args, "global", false);
            if (global == (path != null)) {
                throw new IllegalArgumentException("Specify exactly one namespace path or global destination");
            }
            Namespace destination = global ? session.program().getGlobalNamespace()
                : new NamespaceSupport(session).resolve(path);
            JsonObject before = symbolToJson(symbol);
            boolean changed = !symbol.getParentNamespace().equals(destination);
            // Ghidra permits duplicate labels at different addresses. Moving a named
            // symbol must not silently introduce another same-name destination member.
            if (changed) {
                for (Symbol other : symbolsNamed(session.program().getSymbolTable(), symbol.getName())) {
                    session.monitor().checkCancelled();
                    if (other.getID() != symbol.getID() && other.getParentNamespace().equals(destination)) {
                        JsonObject detail = new JsonObject();
                        detail.add("conflict", symbolToJson(other));
                        throw new JsonProtocol.CommandException("Destination already contains a symbol named "
                            + symbol.getName(), detail);
                    }
                }
            }
            Function function = symbol.getSymbolType() == SymbolType.FUNCTION
                ? (Function) symbol.getObject() : null;
            JsonObject functionBefore = function == null ? null : functionMoveSnapshot(function);
            Set<Long> typesBefore = function == null ? null : dataTypeIds();
            if (changed) symbol.setNamespace(destination);
            if (symbol.isDeleted() || !symbol.getParentNamespace().equals(destination)
                    || !symbol.getName().equals(before.get("name").getAsString())
                    || !Long.toString(symbol.getID()).equals(before.get("id").getAsString())) {
                throw new IllegalStateException("Ghidra did not preserve the symbol identity while moving it");
            }
            JsonObject result = new JsonObject();
            result.addProperty("status", changed ? "moved" : "unchanged");
            result.add("before", before);
            result.add("after", symbolToJson(symbol));
            if (function != null) {
                result.add("function_before", functionBefore);
                result.add("function_after", functionMoveSnapshot(function));
                JsonArray createdTypes = new JsonArray();
                var types = session.program().getDataTypeManager().getAllDataTypes();
                while (types.hasNext()) {
                    session.monitor().checkCancelled();
                    DataType type = types.next();
                    long id = session.program().getDataTypeManager().getID(type);
                    if (!typesBefore.contains(id)) {
                        JsonObject row = new JsonObject();
                        row.addProperty("id", Long.toString(id));
                        row.addProperty("path", type.getPathName());
                        row.addProperty("size", type.getLength());
                        createdTypes.add(row);
                    }
                }
                result.add("created_types", createdTypes);
            }
            return result;
        } catch (Exception e) {
            return errorResult("Failed to move symbol: " + e.getMessage(), e);
        }
    }

    private JsonObject functionMoveSnapshot(Function function) throws CancelledException {
        FunctionQueries queries = new FunctionQueries(session, new AddressResolver(session));
        JsonObject result = queries.signatureDetailsToJson(function);
        result.addProperty("signature", function.getPrototypeString(false, false));
        result.addProperty("calling_convention", function.getCallingConventionName());
        return result;
    }

    private Set<Long> dataTypeIds() throws CancelledException {
        Set<Long> ids = new HashSet<>();
        var manager = session.program().getDataTypeManager();
        var types = manager.getAllDataTypes();
        while (types.hasNext()) {
            session.monitor().checkCancelled();
            ids.add(manager.getID(types.next()));
        }
        return ids;
    }

    public JsonObject handleSetPrimary(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");
        try {
            Symbol symbol = resolveLocalTarget(args, true);
            SymbolTable table = session.program().getSymbolTable();
            for (Symbol other : table.getSymbols(symbol.getAddress())) {
                if (other.getSymbolType() == SymbolType.FUNCTION) {
                    throw new IllegalArgumentException("A function symbol is primary at this address; use function rename to change its name");
                }
            }
            JsonObject before = symbolToJson(symbol);
            Symbol previousPrimary = table.getPrimarySymbol(symbol.getAddress());
            JsonObject previous = previousPrimary == null ? null : symbolToJson(previousPrimary);
            boolean changed = symbol.setPrimary();
            if (!symbol.isPrimary() || (!changed && !before.get("is_primary").getAsBoolean())) {
                throw new IllegalStateException("Ghidra refused to make the label primary");
            }
            JsonObject result = new JsonObject();
            result.addProperty("status", changed ? "updated" : "unchanged");
            result.add("before", before);
            result.add("after", symbolToJson(symbol));
            result.add("previous_primary", previous);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to set primary symbol: " + e.getMessage(), e);
        }
    }

    public JsonObject handleSymbolDelete(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String name = getArgString(args, "name");
        if (name == null) return errorResult("Symbol name required");
        try {
            SymbolTable symbolTable = session.program().getSymbolTable();
            List<Symbol> toDelete = resolveScopedSymbols(symbolTable, name, args);
            rejectNamespaceEdits(toDelete);
            for (Symbol symbol : toDelete) {
                if (symbol.getSymbolType() == SymbolType.LIBRARY
                        && symbolTable.getChildren(symbol).hasNext()) {
                    throw new IllegalArgumentException(
                        "Library contains external imports; delete them before deleting the library");
                }
            }
            List<JsonObject> selected = new ArrayList<>();
            JsonArray deleted = new JsonArray();
            JsonArray failed = new JsonArray();
            JsonArray notAttempted = new JsonArray();
            for (Symbol symbol : toDelete) {
                JsonObject snapshot = symbolToJson(symbol);
                selected.add(snapshot);
                if (symbol.isDynamic()) {
                    failed.add(deletionFailureTarget(snapshot,
                        "Dynamic symbols are generated from references and cannot be deleted"));
                } else if (symbol.getID() == Namespace.GLOBAL_NAMESPACE_ID) {
                    failed.add(deletionFailureTarget(snapshot, "The global namespace cannot be deleted"));
                } else {
                    notAttempted.add(snapshot);
                }
            }
            if (failed.size() != 0)
                throw deletionFailure(name, deleted, failed, notAttempted);
            notAttempted = new JsonArray();

            for (int i = 0; i < toDelete.size(); i++) {
                try {
                    session.monitor().checkCancelled();
                    if (!toDelete.get(i).delete())
                        throw new IllegalStateException("Ghidra refused to delete symbol");
                    deleted.add(selected.get(i));
                } catch (Exception e) {
                    failed.add(deletionFailureTarget(selected.get(i),
                        e.getMessage() == null ? e.toString() : e.getMessage()));
                    for (int j = i + 1; j < selected.size(); j++) notAttempted.add(selected.get(j));
                    throw deletionFailure(name, deleted, failed, notAttempted);
                }
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "deleted");
            result.addProperty("name", name);
            result.addProperty("count", deleted.size());
            result.add("deleted", deleted);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to delete symbol: " + e.getMessage(), e);
        }
    }

    private JsonObject deletionFailureTarget(JsonObject symbol, String reason) {
        JsonObject failure = symbol.deepCopy();
        failure.addProperty("reason", reason);
        return failure;
    }

    private JsonProtocol.CommandException deletionFailure(String name, JsonArray deleted,
            JsonArray failed, JsonArray notAttempted) {
        JsonObject detail = new JsonObject();
        detail.addProperty("name", name);
        detail.add("attempted_deleted", deleted);
        detail.add("failed", failed);
        detail.add("not_attempted", notAttempted);
        String reason = failed.get(0).getAsJsonObject().get("reason").getAsString();
        return new JsonProtocol.CommandException(reason, detail);
    }

    public JsonObject handleSymbolRename(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String oldName = getArgString(args, "old_name");
        String newName = getArgString(args, "new_name");
        if (oldName == null || newName == null) {
            return errorResult("old_name and new_name required");
        }
        try {
            SymbolTable symbolTable = session.program().getSymbolTable();
            List<Symbol> toRename = resolveScopedSymbols(symbolTable, oldName, args);
            rejectNamespaceEdits(toRename);

            JsonArray renamed = new JsonArray();
            for (Symbol s : toRename) {
                session.monitor().checkCancelled();
                JsonObject entry = new JsonObject();
                entry.addProperty("address", AddressCodec.format(s.getAddress()));
                s.setName(newName, SourceType.USER_DEFINED);
                renamed.add(entry);
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "renamed");
            result.addProperty("old_name", oldName);
            result.addProperty("new_name", newName);
            result.add("addresses", renamed);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to rename symbol: " + e.getMessage());
        }
    }

    private void rejectNamespaceEdits(List<Symbol> symbols) {
        for (Symbol symbol : symbols) {
            if (symbol.getSymbolType() == SymbolType.NAMESPACE || symbol.getSymbolType() == SymbolType.CLASS) {
                throw new IllegalArgumentException("Use namespace rename/delete to edit a namespace or class");
            }
        }
    }

    public JsonObject handleSymbolExternals(JsonObject args) throws CancelledException {
        if (session.program() == null) {
            return errorResult("No program loaded");
        }

        int limit = getNonnegativeIntArg(args, "limit", 0);
        JsonArray imports = new JsonArray();
        SymbolTable symbolTable = session.program().getSymbolTable();
        ExternalManager extMgr = session.program().getExternalManager();

        SymbolIterator extSymbols = symbolTable.getExternalSymbols();
        int count = 0;
        while (extSymbols.hasNext()) {
            if (limit > 0 && count >= limit) break;
            session.monitor().checkCancelled();
            Symbol symbol = extSymbols.next();
            ExternalLocation extLoc = extMgr.getExternalLocation(symbol);
            if (extLoc != null) {
                JsonObject importData = new JsonObject();
                importData.addProperty("name", symbol.getName());
                importData.addProperty("address", AddressCodec.format(symbol.getAddress()));
                importData.addProperty("library", extLoc.getLibraryName());
                imports.add(importData);
                count++;
            }
        }

        JsonObject result = new JsonObject();
        result.add("externals", imports);
        result.addProperty("count", imports.size());
        return result;
    }

    public JsonObject handleSymbolEntryPoints(JsonObject args) throws CancelledException {
        if (session.program() == null) {
            return errorResult("No program loaded");
        }

        int limit = getNonnegativeIntArg(args, "limit", 0);
        JsonArray exports = new JsonArray();
        SymbolTable symbolTable = session.program().getSymbolTable();

        SymbolIterator symIter = symbolTable.getSymbolIterator();
        int count = 0;
        while (symIter.hasNext()) {
            if (limit > 0 && count >= limit) break;
            session.monitor().checkCancelled();
            Symbol symbol = symIter.next();
            if (symbol.isExternalEntryPoint()) {
                JsonObject exportData = new JsonObject();
                exportData.addProperty("name", symbol.getName());
                exportData.addProperty("address", AddressCodec.format(symbol.getAddress()));
                exports.add(exportData);
                count++;
            }
        }

        JsonObject result = new JsonObject();
        result.add("entry_points", exports);
        result.addProperty("count", exports.size());
        return result;
    }
}
