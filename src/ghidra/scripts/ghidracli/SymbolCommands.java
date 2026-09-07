package ghidracli;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
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

            JsonObject symData = new JsonObject();
            symData.addProperty("name", name);
            symData.addProperty("address", symbol.getAddress().toString());
            symData.addProperty("type", symbol.getSymbolType().toString());
            symData.addProperty("source", symbol.getSource().toString());
            symData.addProperty("is_primary", symbol.isPrimary());
            symbols.add(symData);
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
                        JsonObject symData = new JsonObject();
                        symData.addProperty("name", s.getName());
                        symData.addProperty("address", s.getAddress().toString());
                        symData.addProperty("type", s.getSymbolType().toString());
                        symData.addProperty("source", s.getSource().toString());
                        syms.add(symData);
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
            JsonObject symData = new JsonObject();
            symData.addProperty("name", s.getName());
            symData.addProperty("address", s.getAddress().toString());
            symData.addProperty("type", s.getSymbolType().toString());
            symData.addProperty("source", s.getSource().toString());
            syms.add(symData);
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

    /** Strip an optional 0x/0X prefix and lowercase, for tolerant address comparison. */
    private String normalizeAddressForCompare(String addr) {
        if (addr == null) return null;
        String a = addr.trim().toLowerCase();
        if (a.startsWith("0x")) a = a.substring(2);
        return a;
    }

    /**
     * Resolve exactly which symbols named `name` a mutation should touch.
     *
     * Ghidra auto-generates names (`caseD_XX`, `LAB_XXXX`, ...) that are
     * routinely reused across unrelated addresses program-wide, so a bare
     * name is not a safe mutation target on its own: without this guard,
     * `symbol rename`/`symbol delete` would silently touch every symbol
     * sharing that name, not just the one address the caller meant.
     *
     * When `addresses` is non-empty, scope to exactly those addresses
     * (erroring if any requested address has no matching symbol). When it's
     * empty and more than one symbol shares `name`, refuse to guess.
     */
    private List<Symbol> resolveScopedSymbols(SymbolTable symbolTable, String name, String[] addresses)
            throws Exception {
        SymbolIterator syms = symbolTable.getSymbols(name);
        List<Symbol> all = new ArrayList<>();
        while (syms.hasNext()) {
            all.add(syms.next());
        }
        if (all.isEmpty()) {
            throw new IllegalArgumentException("Symbol not found: " + name);
        }

        if (addresses != null && addresses.length > 0) {
            Set<String> wanted = new HashSet<>();
            for (String a : addresses) wanted.add(normalizeAddressForCompare(a));
            List<Symbol> scoped = new ArrayList<>();
            for (Symbol s : all) {
                if (wanted.contains(normalizeAddressForCompare(s.getAddress().toString()))) {
                    scoped.add(s);
                }
            }
            if (scoped.isEmpty()) {
                throw new IllegalArgumentException(
                    "No symbol named '" + name + "' at the given address(es)");
            }
            return scoped;
        }

        if (all.size() > 1) {
            StringBuilder addrs = new StringBuilder();
            for (Symbol s : all) {
                if (addrs.length() > 0) addrs.append(", ");
                addrs.append(s.getAddress().toString());
            }
            throw new IllegalArgumentException("'" + name + "' matches " + all.size()
                + " symbols at addresses [" + addrs + "] -- pass explicit address(es) to pick "
                + "one, or request all of them explicitly");
        }

        return all;
    }

    JsonObject handleSymbolDelete(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String name = getArgString(args, "name");
        if (name == null) return errorResult("Symbol name required");
        String[] addresses = getArgStringArray(args, "addresses");

        try {
            SymbolTable symbolTable = session.program().getSymbolTable();
            List<Symbol> toDelete = resolveScopedSymbols(symbolTable, name, addresses);

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
        String[] addresses = getArgStringArray(args, "addresses");

        try {
            SymbolTable symbolTable = session.program().getSymbolTable();
            List<Symbol> toRename = resolveScopedSymbols(symbolTable, oldName, addresses);

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
