package ghidracli;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonElement;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import static ghidracli.JsonProtocol.errorResult;
import static ghidracli.JsonProtocol.getArgInt;
import static ghidracli.JsonProtocol.getArgString;
import static ghidracli.JsonProtocol.getArgStringArray;

final class SymbolCommands {
    private final ProgramSession session;

    SymbolCommands(ProgramSession session) {
        this.session = session;
    }

    JsonObject handleSymbolList(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        int limit = getArgInt(args, "limit", 0);
        String nameFilter = getArgString(args, "filter");

        SymbolTable symbolTable = session.program().getSymbolTable();
        JsonArray symbols = new JsonArray();
        int count = 0;

        SymbolIterator symIter = symbolTable.getAllSymbols(true);
        while (symIter.hasNext()) {
            if (limit > 0 && count >= limit) break;

            Symbol symbol = symIter.next();
            String name = symbol.getName();

            if (nameFilter != null && !name.toLowerCase().contains(nameFilter.toLowerCase())) {
                continue;
            }

            symbols.add(symbolToJson(symbol));
            count++;
        }

        JsonObject result = new JsonObject();
        result.add("symbols", symbols);
        result.addProperty("count", symbols.size());
        return result;
    }

    JsonObject handleSymbolGet(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String addressOrName = getArgString(args, "name");
        if (addressOrName == null || addressOrName.isEmpty()) {
            return errorResult("No symbol name or address provided");
        }

        SymbolTable symbolTable = session.program().getSymbolTable();

        // Try as address first
        boolean looksLikeAddress = addressOrName.startsWith("0x") ||
            addressOrName.chars().allMatch(c -> "0123456789abcdefABCDEF".indexOf(c) >= 0);

        if (looksLikeAddress) {
            try {
                Address addr = session.program().getAddressFactory().getAddress(addressOrName);
                if (addr != null) {
                    Symbol[] symbolsAtAddr = symbolTable.getSymbols(addr);
                    if (symbolsAtAddr.length == 0) {
                        return errorResult("No symbol at address: " + addressOrName);
                    }
                    JsonArray syms = new JsonArray();
                    for (Symbol s : symbolsAtAddr) {
                        syms.add(symbolToJson(s));
                    }
                    JsonObject result = new JsonObject();
                    result.add("symbols", syms);
                    return result;
                }
            } catch (Exception e) {
                // fall through to name lookup
            }
        }

        // Try as name
        SymbolIterator symsByName = symbolTable.getSymbols(addressOrName);
        JsonArray syms = new JsonArray();
        while (symsByName.hasNext()) {
            Symbol s = symsByName.next();
            syms.add(symbolToJson(s));
        }

        if (syms.size() == 0) {
            return errorResult("Symbol not found: " + addressOrName);
        }

        JsonObject result = new JsonObject();
        result.add("symbols", syms);
        return result;
    }

    JsonObject handleSymbolCreate(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String addressStr = getArgString(args, "address");
        String name = getArgString(args, "name");
        if (addressStr == null || name == null) {
            return errorResult("Address and name required");
        }

        try {
            Address addr = session.program().getAddressFactory().getAddress(addressStr);
            if (addr == null) return errorResult("Invalid address: " + addressStr);

            ProgramTransaction transaction = session.transaction("Create symbol");
            try {
                SymbolTable symbolTable = session.program().getSymbolTable();
                symbolTable.createLabel(addr, name, SourceType.USER_DEFINED);
                transaction.end(true);
            } catch (Exception e) {
                transaction.end(true);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "created");
            result.addProperty("address", addressStr);
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
        result.addProperty("address", symbol.getAddress().toString());
        result.addProperty("namespace", symbol.getParentNamespace().getName(true));
        result.addProperty("type", symbol.getSymbolType().toString());
        result.addProperty("source", symbol.getSource().toString());
        result.addProperty("is_primary", symbol.isPrimary());
        result.addProperty("address_space", symbol.getAddress().getAddressSpace().getName());
        result.addProperty("is_default_address_space", symbol.getAddress().getAddressSpace().equals(
            session.program().getAddressFactory().getDefaultAddressSpace()));
        return result;
    }

    /** Revalidate the entire selection before opening a mutation transaction. */
    private List<Symbol> resolveScopedSymbols(SymbolTable table, String name, JsonObject args) {
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
        SymbolIterator syms = table.getSymbols(name);
        List<Symbol> all = new ArrayList<>();
        while (syms.hasNext()) all.add(syms.next());
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

            ProgramTransaction transaction = session.transaction("Delete symbol");
            try {
                for (Symbol s : toDelete) {
                    s.delete();
                }
                transaction.end(true);
            } catch (Exception e) {
                transaction.end(true);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "deleted");
            result.addProperty("name", name);
            result.addProperty("count", toDelete.size());
            return result;
        } catch (Exception e) {
            return errorResult("Failed to delete symbol: " + e.getMessage());
        }
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
            ProgramTransaction transaction = session.transaction("Rename symbol");
            try {
                for (Symbol s : toRename) {
                    JsonObject entry = new JsonObject();
                    entry.addProperty("address", s.getAddress().toString());
                    s.setName(newName, SourceType.USER_DEFINED);
                    renamed.add(entry);
                }
                transaction.end(true);
            } catch (Exception e) {
                transaction.end(true);
                throw e;
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
