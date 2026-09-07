package ghidracli;

import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import java.util.ArrayList;
import java.util.List;
import static ghidracli.JsonProtocol.errorResult;
import static ghidracli.JsonProtocol.getArgString;

final class SearchCommands {
    private final ProgramSession session;
    private final FunctionQueries functionQueries;

    SearchCommands(ProgramSession session, FunctionQueries functionQueries) {
        this.session = session;
        this.functionQueries = functionQueries;
    }

    JsonObject handleFindString(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String pattern = getArgString(args, "pattern");
        if (pattern == null) pattern = "";

        try {
            JsonArray results = new JsonArray();

            // Phase 1: Search pre-analyzed string data types from the listing.
            // This is fast and returns strings Ghidra's analyzer has already classified.
            Listing listing = session.program().getListing();
            DataIterator dataIter = listing.getDefinedData(true);

            while (dataIter.hasNext()) {
                Data data = dataIter.next();
                if (data.hasStringValue()) {
                    try {
                        String val = data.getValue().toString();
                        if (pattern.isEmpty() || val.toLowerCase().contains(pattern.toLowerCase())) {
                            JsonObject item = new JsonObject();
                            item.addProperty("address", data.getAddress().toString());
                            item.addProperty("value", val);
                            item.addProperty("length", data.getLength());
                            results.add(item);
                        }
                    } catch (Exception e) { /* skip */ }
                }
            }

            // Phase 2: If listing search found nothing and we have a pattern,
            // fall back to raw memory scanning. This catches strings that Ghidra's
            // analyzer didn't classify as string data types (common on PE binaries,
            // and on macOS arm64 Rust binaries where literals stay undefined).
            //
            // This is a heuristic: it walks back to the start of the surrounding
            // printable run and reads forward, capped at MEM_SCAN_MAX_LEN. Strings
            // without a NUL/non-printable separator (e.g. packed Rust &str literals)
            // can't have their exact boundaries recovered from raw bytes alone, so
            // these results are marked with "source":"memory-scan".
            if (results.size() == 0 && !pattern.isEmpty()) {
                final int MEM_SCAN_MAX_LEN = 256;
                Memory memory = session.program().getMemory();
                byte[] searchBytes = pattern.getBytes(java.nio.charset.StandardCharsets.UTF_8);

                Address addr = memory.getMinAddress();
                while (addr != null && results.size() < 100) {
                    Address found = memory.findBytes(addr, searchBytes, null, true, session.monitor());
                    if (found == null) break;

                    // Walk back to the start of the printable run so the result
                    // isn't truncated to the match offset (e.g. losing "Hello, ").
                    Address start = backScanToStringStart(memory, found, MEM_SCAN_MAX_LEN);
                    String extracted = extractStringAt(memory, start, MEM_SCAN_MAX_LEN);
                    if (extracted != null && !extracted.isEmpty()) {
                        JsonObject item = new JsonObject();
                        item.addProperty("address", start.toString());
                        item.addProperty("value", extracted);
                        item.addProperty("length", extracted.length());
                        item.addProperty("source", "memory-scan");
                        results.add(item);
                    }

                    // Advance past this match (use the matched pattern length so we
                    // don't loop forever if extraction came back empty).
                    addr = found.add(Math.max(1, searchBytes.length));
                }
            }

            JsonObject result = new JsonObject();
            result.add("results", results);
            result.addProperty("count", results.size());
            return result;
        } catch (Exception e) {
            return errorResult("Failed to find strings: " + e.getMessage());
        }
    }

    /**
     * Walk backward from a match address to the start of the surrounding
     * printable-ASCII run (stopping at a null/non-printable byte, the memory
     * block start, or after maxBack bytes). Returns the start address.
     *
     * For NUL-terminated strings this recovers the true start. For packed
     * non-terminated strings (Rust &str literals) there is no separator, so
     * the run may include preceding literals — bounded by maxBack.
     */
    private Address backScanToStringStart(Memory memory, Address matchAddr, int maxBack) {
        Address start = matchAddr;
        try {
            for (int i = 0; i < maxBack; i++) {
                Address prev = start.subtract(1);
                if (prev == null || !memory.contains(prev)) break;
                byte b = memory.getByte(prev);
                if (b == 0 || b < 0x20 || b > 0x7e) break;
                start = prev;
            }
        } catch (Exception e) {
            // Hit a block boundary or unreadable byte; current start is fine.
        }
        return start;
    }

    /**
     * Extract a printable string starting at the given address.
     * Reads until a null byte, non-printable character, or maxLen is reached.
     */
    private String extractStringAt(Memory memory, Address addr, int maxLen) {
        try {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < maxLen; i++) {
                byte b = memory.getByte(addr.add(i));
                if (b == 0) break;
                if (b < 0x20 || b > 0x7e) break; // non-printable ASCII
                sb.append((char) b);
            }
            return sb.length() > 0 ? sb.toString() : null;
        } catch (Exception e) {
            return null;
        }
    }

    JsonObject handleStringRefs(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String pattern = getArgString(args, "string");
        if (pattern == null || pattern.isEmpty()) return errorResult("String pattern required");

        try {
            Listing listing = session.program().getListing();
            ReferenceManager refMgr = session.program().getReferenceManager();
            FunctionManager fm = session.program().getFunctionManager();
            JsonArray results = new JsonArray();

            DataIterator dataIter = listing.getDefinedData(true);
            while (dataIter.hasNext()) {
                Data data = dataIter.next();
                if (!data.hasStringValue()) continue;

                String val = data.getDefaultValueRepresentation();
                if (val != null && val.length() >= 2 && val.startsWith("\"") && val.endsWith("\"")) {
                    val = val.substring(1, val.length() - 1);
                }
                if (val == null || !val.toLowerCase().contains(pattern.toLowerCase())) continue;

                Address strAddr = data.getAddress();
                for (Reference ref : refMgr.getReferencesTo(strAddr)) {
                    JsonObject item = new JsonObject();
                    item.addProperty("string_address", strAddr.toString());
                    item.addProperty("string_value", val);
                    item.addProperty("from", ref.getFromAddress().toString());
                    item.addProperty("ref_type", ref.getReferenceType().toString());
                    Function fn = fm.getFunctionContaining(ref.getFromAddress());
                    if (fn != null) {
                        item.addProperty("from_function", fn.getName());
                    } else {
                        item.add("from_function", JsonNull.INSTANCE);
                    }
                    results.add(item);
                }
            }

            JsonObject result = new JsonObject();
            result.add("results", results);
            result.addProperty("count", results.size());
            result.addProperty("pattern", pattern);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to find string refs: " + e.getMessage());
        }
    }

    JsonObject handleFindBytes(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String hexPattern = getArgString(args, "hex");
        if (hexPattern == null || hexPattern.isEmpty()) {
            return errorResult("No hex pattern provided");
        }

        try {
            String hexClean = hexPattern.replace("0x", "").replace(" ", "");
            byte[] searchBytes = new byte[hexClean.length() / 2];
            for (int i = 0; i < searchBytes.length; i++) {
                searchBytes[i] = (byte) Integer.parseInt(hexClean.substring(i * 2, i * 2 + 2), 16);
            }

            Memory memory = session.program().getMemory();
            JsonArray results = new JsonArray();

            Address addr = memory.getMinAddress();
            while (addr != null && results.size() < 100) {
                Address found = memory.findBytes(addr, searchBytes, null, true, session.monitor());
                if (found == null) break;
                JsonObject item = new JsonObject();
                item.addProperty("address", found.toString());
                results.add(item);
                addr = found.add(1);
            }

            JsonObject result = new JsonObject();
            result.add("results", results);
            result.addProperty("count", results.size());
            return result;
        } catch (Exception e) {
            return errorResult("Failed to find bytes: " + e.getMessage());
        }
    }

    JsonObject handleFindFunction(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String pattern = getArgString(args, "pattern");
        if (pattern == null) pattern = "";

        try {
            FunctionManager fm = session.program().getFunctionManager();
            JsonArray results = new JsonArray();
            boolean isWildcard = pattern.contains("*");

            FunctionIterator iter = fm.getFunctions(true);
            while (iter.hasNext()) {
                Function func = iter.next();
                String name = func.getName();
                boolean matches;

                if (isWildcard) {
                    // Simple wildcard matching: convert * to regex .*
                    String regex = pattern.replace(".", "\\.").replace("*", ".*");
                    matches = name.matches(regex);
                } else {
                    matches = name.toLowerCase().contains(pattern.toLowerCase());
                }

                if (matches) {
                    JsonObject item = new JsonObject();
                    item.addProperty("name", name);
                    item.addProperty("address", func.getEntryPoint().toString());
                    item.addProperty("size", func.getBody().getNumAddresses());
                    results.add(item);
                }
            }

            JsonObject result = new JsonObject();
            result.add("results", results);
            result.addProperty("count", results.size());
            return result;
        } catch (Exception e) {
            return errorResult("Failed to find functions: " + e.getMessage());
        }
    }

    JsonObject handleFindCalls(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String functionTarget = getArgString(args, "function");
        if (functionTarget == null || functionTarget.isEmpty()) {
            return errorResult("No function target provided");
        }

        try {
            FunctionManager fm = session.program().getFunctionManager();
            Function targetFunc = functionQueries.findFunctionByNameOrAddress(functionTarget);
            if (targetFunc == null) {
                return errorResult(functionQueries.buildFunctionTargetHint(functionTarget));
            }

            ReferenceManager refMgr = session.program().getReferenceManager();
            JsonArray results = new JsonArray();
            ghidra.program.model.address.AddressIterator srcIter =
                refMgr.getReferenceSourceIterator(targetFunc.getBody(), true);
            while (srcIter.hasNext()) {
                Address fromAddr = srcIter.next();
                for (Reference ref : refMgr.getReferencesFrom(fromAddr)) {
                    if (!ref.getReferenceType().isCall()) continue;
                    Address toAddr = ref.getToAddress();
                    Function calleeFunc = fm.getFunctionAt(toAddr);
                    if (calleeFunc == null) calleeFunc = fm.getFunctionContaining(toAddr);

                    JsonObject item = new JsonObject();
                    item.addProperty("call_site", fromAddr.toString());
                    item.addProperty("callee",
                        calleeFunc != null ? calleeFunc.getName() : toAddr.toString());
                    item.addProperty("callee_address", toAddr.toString());
                    item.addProperty("type", ref.getReferenceType().toString());
                    results.add(item);
                }
            }

            JsonObject result = new JsonObject();
            result.add("results", results);
            result.addProperty("count", results.size());
            result.addProperty("target", functionTarget);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to find calls: " + e.getMessage());
        }
    }

    JsonObject handleFindCrypto() {
        if (session.program() == null) return errorResult("No program loaded");

        try {
            Memory memory = session.program().getMemory();
            JsonArray results = new JsonArray();

            String[][] cryptoPatterns = {
                {"AES S-box", "637c777bf26b6fc53001672bfed7ab76"},
                {"SHA-256", "428a2f98d728ae227137449123ef65cd"},
                {"MD5", "d76aa478e8c7b756242070db01234567"}
            };

            for (String[] cp : cryptoPatterns) {
                String name = cp[0];
                String hexPattern = cp[1];
                byte[] searchBytes = new byte[hexPattern.length() / 2];
                for (int i = 0; i < searchBytes.length; i++) {
                    searchBytes[i] = (byte) Integer.parseInt(hexPattern.substring(i * 2, i * 2 + 2), 16);
                }

                Address addr = memory.getMinAddress();
                Address found = memory.findBytes(addr, searchBytes, null, true, session.monitor());
                if (found != null) {
                    JsonObject item = new JsonObject();
                    item.addProperty("type", name);
                    item.addProperty("address", found.toString());
                    item.addProperty("pattern", hexPattern);
                    results.add(item);
                }
            }

            JsonObject result = new JsonObject();
            result.add("results", results);
            result.addProperty("count", results.size());
            return result;
        } catch (Exception e) {
            return errorResult("Failed to find crypto: " + e.getMessage());
        }
    }

    JsonObject handleFindInteresting() {
        if (session.program() == null) return errorResult("No program loaded");

        try {
            FunctionManager fm = session.program().getFunctionManager();
            ReferenceManager refMgr = session.program().getReferenceManager();
            List<JsonObject> resultsList = new ArrayList<>();

            String[] suspiciousNames = {"password", "key", "encrypt", "decrypt", "crypt",
                "auth", "login", "admin", "secret"};

            FunctionIterator iter = fm.getFunctions(true);
            while (iter.hasNext()) {
                Function func = iter.next();
                String funcName = func.getName();
                Address funcAddr = func.getEntryPoint();
                long funcSize = func.getBody().getNumAddresses();

                int xrefCount = 0;
                for (Reference ref : refMgr.getReferencesTo(funcAddr)) {
                    xrefCount++;
                }

                JsonArray reasons = new JsonArray();

                if (funcSize > 1000) {
                    reasons.add(new JsonPrimitive("large function (" + funcSize + " bytes)"));
                }
                if (xrefCount > 50) {
                    reasons.add(new JsonPrimitive("many xrefs (" + xrefCount + ")"));
                }
                for (String sus : suspiciousNames) {
                    if (funcName.toLowerCase().contains(sus)) {
                        reasons.add(new JsonPrimitive("suspicious name"));
                        break;
                    }
                }

                if (reasons.size() > 0) {
                    JsonObject item = new JsonObject();
                    item.addProperty("name", funcName);
                    item.addProperty("address", funcAddr.toString());
                    item.addProperty("size", funcSize);
                    item.addProperty("xrefs", xrefCount);
                    item.add("reasons", reasons);
                    resultsList.add(item);
                }
            }

            // Sort by number of reasons (descending)
            resultsList.sort((a, b) -> b.getAsJsonArray("reasons").size() - a.getAsJsonArray("reasons").size());

            JsonArray results = new JsonArray();
            int limit = Math.min(50, resultsList.size());
            for (int i = 0; i < limit; i++) {
                results.add(resultsList.get(i));
            }

            JsonObject result = new JsonObject();
            result.add("results", results);
            result.addProperty("count", resultsList.size());
            return result;
        } catch (Exception e) {
            return errorResult("Failed to find interesting functions: " + e.getMessage());
        }
    }
}
