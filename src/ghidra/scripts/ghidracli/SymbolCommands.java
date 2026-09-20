package ghidracli;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonElement;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import static ghidracli.JsonProtocol.errorResult;
import static ghidracli.JsonProtocol.getArgString;
import static ghidracli.JsonProtocol.getArgStringArray;

final class SymbolCommands {
    private final ProgramSession session;

    SymbolCommands(ProgramSession session) {
        this.session = session;
    }

    JsonObject handleSymbolList(JsonObject args) throws ghidra.util.exception.CancelledException {
        if (session.program() == null) return errorResult("No program loaded");

        ListQuery query = new ListQuery(session, args);

        SymbolTable symbolTable = session.program().getSymbolTable();
        JsonArray symbols = new JsonArray();

        SymbolIterator symIter = symbolTable.getAllSymbols(true);
        while (symIter.hasNext()) {
            if (query.isFull()) break;

            Symbol symbol = symIter.next();
            String name = symbol.getName();

            if (!query.include(name)) {
                continue;
            }

            symbols.add(symbolToJson(symbol));
            query.record();
        }

        JsonObject result = new JsonObject();
        result.add("symbols", symbols);
        result.addProperty("count", symbols.size());
        return result;
    }

    JsonObject handleSymbolGet(JsonObject args) throws CancelledException {
        return lookupSymbols(args, false);
    }

    JsonObject handleSymbolGetByName(JsonObject args) throws CancelledException {
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

    JsonObject handleSymbolCreate(JsonObject args) {
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
        List<Symbol> selected = new ArrayList<>();
        if (args.has("targets")) {
            JsonArray targets = args.getAsJsonArray("targets");
            if (targets.size() == 0) throw new IllegalArgumentException("Symbol targets cannot be empty");
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

        // Legacy address-scoped requests must validate every requested address.
        // Multiple symbols at one address require stable IDs to distinguish namespaces.
        String[] addresses = getArgStringArray(args, "addresses");
        List<Symbol> all = symbolsNamed(table, name);
        if (addresses.length > 0) {
            Set<Address> seen = new HashSet<>();
            for (String value : addresses) {
                Address address = new AddressResolver(session).parseAddress(value);
                if (address == null) throw new IllegalArgumentException("Invalid address: " + value);
                if (!seen.add(address)) continue;
                Symbol match = null;
                for (Symbol symbol : all) {
                    if (!symbol.getAddress().equals(address)) continue;
                    if (match != null) throw new IllegalArgumentException(
                        "Ambiguous symbol at " + value + "; use stable symbol targets");
                    match = symbol;
                }
                if (match == null) throw new IllegalArgumentException(
                    "No symbol named '" + name + "' at address " + value);
                selected.add(match);
            }
            return selected;
        }
        if (all.isEmpty()) throw new IllegalArgumentException("Symbol not found: " + name);
        if (all.size() > 1) throw new IllegalArgumentException(
            "'" + name + "' matches " + all.size() + " symbols; pass explicit address(es)");
        return all;
    }

    JsonObject handleSymbolDelete(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String name = getArgString(args, "name");
        if (name == null) return errorResult("Symbol name required");
        try {
            SymbolTable symbolTable = session.program().getSymbolTable();
            List<Symbol> toDelete = resolveScopedSymbols(symbolTable, name, args);
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

    JsonObject handleSymbolRename(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String oldName = getArgString(args, "old_name");
        String newName = getArgString(args, "new_name");
        if (oldName == null || newName == null) {
            return errorResult("old_name and new_name required");
        }
        try {
            SymbolTable symbolTable = session.program().getSymbolTable();
            List<Symbol> toRename = resolveScopedSymbols(symbolTable, oldName, args);

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
}
