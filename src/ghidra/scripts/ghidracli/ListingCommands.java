package ghidracli;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import static ghidracli.JsonProtocol.errorResult;
import static ghidracli.JsonProtocol.getNonnegativeIntArg;

final class ListingCommands {
    private final ProgramSession session;
    private final StringQueries stringQueries;

    ListingCommands(ProgramSession session, StringQueries stringQueries) {
        this.session = session;
        this.stringQueries = stringQueries;
    }

    JsonObject handleListStrings(JsonObject args) throws ghidra.util.exception.CancelledException {
        if (session.program() == null) {
            return errorResult("No program loaded");
        }

        JsonArray strings = stringQueries.list(args, null);

        JsonObject result = new JsonObject();
        result.add("strings", strings);
        result.addProperty("count", strings.size());
        return result;
    }

    JsonObject handleSymbolExternals(JsonObject args) {
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

    JsonObject handleSymbolEntryPoints(JsonObject args) {
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
            blockData.addProperty("start", AddressCodec.format(block.getStart()));
            blockData.addProperty("end", AddressCodec.format(block.getEnd()));
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
