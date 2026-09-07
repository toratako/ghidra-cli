package ghidracli;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import static ghidracli.JsonProtocol.errorResult;
import static ghidracli.JsonProtocol.getArgInt;
import static ghidracli.JsonProtocol.getArgString;

final class ListingCommands {
    private final ProgramSession session;

    ListingCommands(ProgramSession session) {
        this.session = session;
    }

    JsonObject handleListStrings(JsonObject args) {
        if (session.program() == null) {
            return errorResult("No program loaded");
        }

        int limit = getArgInt(args, "limit", 0);
        String nameFilter = getArgString(args, "filter");

        JsonArray strings = new JsonArray();
        Listing listing = session.program().getListing();
        DataIterator dataIter = listing.getDefinedData(true);
        int count = 0;

        while (dataIter.hasNext()) {
            if (limit > 0 && count >= limit) break;

            Data data = dataIter.next();
            if (data.hasStringValue()) {
                try {
                    String val = data.getValue().toString();

                    if (nameFilter != null && !val.toLowerCase().contains(nameFilter.toLowerCase())) {
                        continue;
                    }

                    JsonObject strData = new JsonObject();
                    strData.addProperty("address", data.getAddress().toString());
                    strData.addProperty("value", val);
                    strData.addProperty("length", val.length());
                    strings.add(strData);
                    count++;
                } catch (Exception e) {
                    // skip
                }
            }
        }

        JsonObject result = new JsonObject();
        result.add("strings", strings);
        result.addProperty("count", strings.size());
        return result;
    }

    JsonObject handleListImports(JsonObject args) {
        if (session.program() == null) {
            return errorResult("No program loaded");
        }

        int limit = getArgInt(args, "limit", 0);
        JsonArray imports = new JsonArray();
        SymbolTable symbolTable = session.program().getSymbolTable();
        ExternalManager extMgr = session.program().getExternalManager();

        SymbolIterator extSymbols = symbolTable.getExternalSymbols();
        int count = 0;
        while (extSymbols.hasNext()) {
            if (limit > 0 && count >= limit) break;
            Symbol symbol = extSymbols.next();
            ExternalLocation extLoc = extMgr.getExternalLocation(symbol);
            if (extLoc != null) {
                JsonObject importData = new JsonObject();
                importData.addProperty("name", symbol.getName());
                importData.addProperty("address", symbol.getAddress().toString());
                importData.addProperty("library", extLoc.getLibraryName());
                imports.add(importData);
                count++;
            }
        }

        JsonObject result = new JsonObject();
        result.add("imports", imports);
        result.addProperty("count", imports.size());
        return result;
    }

    JsonObject handleListExports(JsonObject args) {
        if (session.program() == null) {
            return errorResult("No program loaded");
        }

        int limit = getArgInt(args, "limit", 0);
        JsonArray exports = new JsonArray();
        SymbolTable symbolTable = session.program().getSymbolTable();

        SymbolIterator symIter = symbolTable.getSymbolIterator();
        int count = 0;
        while (symIter.hasNext()) {
            if (limit > 0 && count >= limit) break;
            Symbol symbol = symIter.next();
            if (symbol.isExternalEntryPoint()) {
                JsonObject exportData = new JsonObject();
                exportData.addProperty("name", symbol.getName());
                exportData.addProperty("address", symbol.getAddress().toString());
                exports.add(exportData);
                count++;
            }
        }

        JsonObject result = new JsonObject();
        result.add("exports", exports);
        result.addProperty("count", exports.size());
        return result;
    }

    JsonObject handleMemoryMap() {
        if (session.program() == null) {
            return errorResult("No program loaded");
        }

        JsonArray blocks = new JsonArray();
        Memory memory = session.program().getMemory();

        for (MemoryBlock block : memory.getBlocks()) {
            StringBuilder perms = new StringBuilder();
            if (block.isRead()) perms.append("r");
            if (block.isWrite()) perms.append("w");
            if (block.isExecute()) perms.append("x");

            JsonObject blockData = new JsonObject();
            blockData.addProperty("name", block.getName());
            blockData.addProperty("start", block.getStart().toString());
            blockData.addProperty("end", block.getEnd().toString());
            blockData.addProperty("size", block.getSize());
            blockData.addProperty("permissions", perms.toString());
            blockData.addProperty("is_initialized", block.isInitialized());
            blockData.addProperty("is_loaded", block.isLoaded());
            blocks.add(blockData);
        }

        JsonObject result = new JsonObject();
        result.add("blocks", blocks);
        result.addProperty("count", blocks.size());
        return result;
    }
}
