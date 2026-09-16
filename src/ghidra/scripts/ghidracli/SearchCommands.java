package ghidracli;

import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.exception.CancelledException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;
import static ghidracli.JsonProtocol.errorResult;
import static ghidracli.JsonProtocol.getArgBool;
import static ghidracli.JsonProtocol.getArgInt;
import static ghidracli.JsonProtocol.getArgString;

final class SearchCommands {
    private final ProgramSession session;
    private final FunctionQueries functionQueries;
    private final AddressResolver addressResolver;

    SearchCommands(ProgramSession session, FunctionQueries functionQueries, AddressResolver addressResolver) {
        this.session = session;
        this.functionQueries = functionQueries;
        this.addressResolver = addressResolver;
    }

    JsonObject handleFindInstruction(JsonObject args) throws Exception {
        if (session.program() == null) return errorResult("No program loaded");
        String pattern = getArgString(args, "pattern");
        if (pattern == null || pattern.isEmpty()) return errorResult("Non-empty pattern required");
        boolean caseSensitive = getArgBool(args, "case_sensitive", false);
        int limit = getArgInt(args, "limit", 0);
        if (limit < 0) return errorResult("Limit must be non-negative (0 means unlimited)");
        AddressSetView range = addressResolver.instructionRange(
            getArgString(args, "start"), getArgString(args, "end"));
        String needle = caseSensitive ? pattern : pattern.toLowerCase(Locale.ROOT);
        JsonArray results = new JsonArray();
        for (Instruction instruction : session.program().getListing().getInstructions(range, true)) {
            session.monitor().checkCancelled();
            Address address = instruction.getAddress();
            // Match start addresses, even if a listing iterator includes a
            // code unit that overlaps the lower boundary.
            if (!range.contains(address)) continue;
            String text = instruction.toString();
            String haystack = caseSensitive ? text : text.toLowerCase(Locale.ROOT);
            if (!haystack.contains(needle)) continue;
            JsonObject row = new JsonObject();
            row.addProperty("address", address.toString());
            row.addProperty("disasm", text);
            Function function = session.program().getFunctionManager().getFunctionContaining(address);
            if (function != null) row.addProperty("function", function.getName());
            results.add(row);
            if (limit > 0 && results.size() >= limit) break;
        }
        JsonObject result = new JsonObject();
        result.add("results", results);
        result.addProperty("count", results.size());
        return result;
    }

    JsonObject handleFindString(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String pattern = getArgString(args, "pattern");
        if (pattern == null) pattern = "";

        try {
            long limit = ListQuery.pageArgument(args, "limit");
            JsonArray results = new JsonArray();

            // Phase 1: Search pre-analyzed string data types from the listing.
            // This is fast and returns strings Ghidra's analyzer has already classified.
            Listing listing = session.program().getListing();
            DataIterator dataIter = listing.getDefinedData(true);

            while (dataIter.hasNext()) {
                session.monitor().checkCancelled();
                if (limit > 0 && results.size() >= limit) break;
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
            // printable run and reads a window large enough for the match (normally
            // capped at MEM_SCAN_MAX_LEN). Strings
            // without a NUL/non-printable separator (e.g. packed Rust &str literals)
            // can't have their exact boundaries recovered from raw bytes alone, so
            // these results are marked with "source":"memory-scan".
            if (results.size() == 0 && !pattern.isEmpty()) {
                final int MEM_SCAN_MAX_LEN = 256;
                Memory memory = session.program().getMemory();
                byte[] searchBytes = pattern.getBytes(java.nio.charset.StandardCharsets.UTF_8);

                Address addr = memory.getMinAddress();
                while (addr != null && (limit == 0 || results.size() < limit)) {
                    session.monitor().checkCancelled();
                    Address found = memory.findBytes(addr, searchBytes, null, true, session.monitor());
                    session.monitor().checkCancelled();
                    if (found == null) break;

                    // Walk back to the start of the printable run so the result
                    // isn't truncated to the match offset (e.g. losing "Hello, ").
                    int windowLength = Math.max(MEM_SCAN_MAX_LEN, searchBytes.length);
                    Address start = backScanToStringStart(memory, found, windowLength - searchBytes.length);
                    String extracted = extractStringAt(memory, start, windowLength);
                    if (extracted.contains(pattern)) {
                        JsonObject item = new JsonObject();
                        item.addProperty("address", start.toString());
                        item.addProperty("value", extracted);
                        item.addProperty("length", extracted.length());
                        item.addProperty("source", "memory-scan");
                        item.addProperty("truncated", hasPrintableNeighbor(memory, start, -1)
                            || hasPrintableNeighbor(memory, start, extracted.length()));
                        results.add(item);
                    }

                    // Advance past this match (use the matched pattern length so we
                    // don't loop forever if extraction came back empty).
                    try {
                        addr = found.addNoWrap(searchBytes.length);
                    } catch (ghidra.program.model.address.AddressOverflowException e) {
                        break;
                    }
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
    private Address backScanToStringStart(Memory memory, Address matchAddr, int maxBack) throws CancelledException {
        Address start = matchAddr;
        try {
            for (int i = 0; i < maxBack; i++) {
                session.monitor().checkCancelled();
                Address prev = start.subtractNoWrap(1);
                if (prev == null || !memory.contains(prev)) break;
                byte b = memory.getByte(prev);
                if (b == 0 || b < 0x20 || b > 0x7e) break;
                start = prev;
            }
        } catch (CancelledException e) {
            throw e;
        } catch (Exception e) {
            // Hit a block boundary or unreadable byte; current start is fine.
        }
        return start;
    }

    /**
     * Extract a printable string starting at the given address.
     * Reads until a null byte, non-printable character, or maxLen is reached.
     */
    private String extractStringAt(Memory memory, Address addr, int maxLen) throws CancelledException {
        StringBuilder sb = new StringBuilder();
        try {
            for (int i = 0; i < maxLen; i++) {
                session.monitor().checkCancelled();
                byte b = memory.getByte(addr.addNoWrap(i));
                if (b < 0x20 || b > 0x7e) break;
                sb.append((char) b);
            }
        } catch (CancelledException e) {
            throw e;
        } catch (Exception e) {
            // Retain the readable prefix at an unmapped/uninitialized boundary.
        }
        return sb.toString();
    }

    private boolean hasPrintableNeighbor(Memory memory, Address start, int offset) {
        try {
            byte b = memory.getByte(start.addNoWrap(offset));
            return b >= 0x20 && b <= 0x7e;
        } catch (Exception e) {
            return false;
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
                session.monitor().checkCancelled();
                Data data = dataIter.next();
                if (!data.hasStringValue()) continue;

                String val = data.getDefaultValueRepresentation();
                if (val != null && val.length() >= 2 && val.startsWith("\"") && val.endsWith("\"")) {
                    val = val.substring(1, val.length() - 1);
                }
                if (val == null || !val.toLowerCase().contains(pattern.toLowerCase())) continue;

                Address strAddr = data.getAddress();
                for (Reference ref : refMgr.getReferencesTo(strAddr)) {
                    session.monitor().checkCancelled();
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
            long limit = ListQuery.pageArgument(args, "limit");
            String hexClean = hexPattern.replace("0x", "").replace(" ", "");
            if (hexClean.isEmpty() || (hexClean.length() % 2) != 0
                    || !hexClean.matches("[0-9a-fA-F]+")) {
                return errorResult("Hex pattern must contain non-empty complete byte pairs");
            }
            byte[] searchBytes = new byte[hexClean.length() / 2];
            for (int i = 0; i < searchBytes.length; i++) {
                searchBytes[i] = (byte) Integer.parseInt(hexClean.substring(i * 2, i * 2 + 2), 16);
            }

            Memory memory = session.program().getMemory();
            JsonArray results = new JsonArray();

            Address addr = memory.getMinAddress();
            while (addr != null && (limit == 0 || results.size() < limit)) {
                session.monitor().checkCancelled();
                Address found = memory.findBytes(addr, searchBytes, null, true, session.monitor());
                session.monitor().checkCancelled();
                if (found == null) break;
                JsonObject item = new JsonObject();
                item.addProperty("address", found.toString());
                results.add(item);
                try {
                    addr = found.addNoWrap(1);
                } catch (ghidra.program.model.address.AddressOverflowException e) {
                    break;
                }
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
            String regex = java.util.Arrays.stream(pattern.split("\\*", -1))
                .map(Pattern::quote).collect(java.util.stream.Collectors.joining(".*"));

            FunctionIterator iter = fm.getFunctions(true);
            while (iter.hasNext()) {
                session.monitor().checkCancelled();
                Function func = iter.next();
                String name = func.getName();
                boolean matches;

                if (isWildcard) {
                    // Only * is special; all other characters are literal.
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

    JsonObject handleFunctionCalls(JsonObject args) {
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
                session.monitor().checkCancelled();
                Address fromAddr = srcIter.next();
                for (Reference ref : refMgr.getReferencesFrom(fromAddr)) {
                    session.monitor().checkCancelled();
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

    /** Search incoming call sites across the program, resolving thunks and import slots. */
    JsonObject handleFindCalls(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");
        String target = getArgString(args, "function");
        if (target == null || target.isEmpty()) return errorResult("No function target provided");
        try {
            FunctionManager fm = session.program().getFunctionManager();
            CallReferences calls = new CallReferences(session, addressResolver);
            Function callee = calls.resolveTarget(target);
            if (callee == null) return errorResult(functionQueries.buildFunctionTargetHint(target));
            java.util.Map<Address, JsonObject> sites = new java.util.TreeMap<>();
            calls.visitCallsTo(callee, (ref, destination) -> {
                Address from = ref.getFromAddress();
                JsonObject row = new JsonObject();
                Function caller = fm.getFunctionContaining(from);
                row.addProperty("call_site", from.toString());
                row.addProperty("caller", caller == null ? null : caller.getName());
                row.addProperty("caller_address", caller == null ? null : caller.getEntryPoint().toString());
                row.addProperty("callee", callee.getName());
                row.addProperty("callee_address", callee.getEntryPoint().toString());
                row.addProperty("type", ref.getReferenceType().toString());
                row.addProperty("via", destination.toString());
                sites.put(from, row);
                return true;
            });
            JsonArray results = new JsonArray();
            sites.values().forEach(results::add);
            JsonObject result = new JsonObject();
            result.add("results", results);
            result.addProperty("count", results.size());
            result.addProperty("target", target);
            return result;
        } catch (Exception error) {
            return errorResult("Failed to find calls: " + error.getMessage());
        }
    }

    JsonObject handleFindCrypto() {
        if (session.program() == null) return errorResult("No program loaded");

        try {
            Memory memory = session.program().getMemory();
            JsonArray results = new JsonArray();

            String[][] cryptoPatterns = {
                {"AES S-box", "637c777bf26b6fc53001672bfed7ab76"},
                // First four 32-bit round constants, in big- and little-endian order.
                {"SHA-256", "428a2f9871374491b5c0fbcfe9b5dba5"},
                {"SHA-256", "982f8a4291443771cffbc0b5a5dbb5e9"},
                {"MD5", "d76aa478e8c7b756242070dbc1bdceee"},
                {"MD5", "78a46ad756b7c7e8db702024eecebdc1"}
            };

            for (String[] cp : cryptoPatterns) {
                session.monitor().checkCancelled();
                String name = cp[0];
                String hexPattern = cp[1];
                byte[] searchBytes = new byte[hexPattern.length() / 2];
                for (int i = 0; i < searchBytes.length; i++) {
                    searchBytes[i] = (byte) Integer.parseInt(hexPattern.substring(i * 2, i * 2 + 2), 16);
                }

                Address addr = memory.getMinAddress();
                Address found = memory.findBytes(addr, searchBytes, null, true, session.monitor());
                session.monitor().checkCancelled();
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

    JsonObject handleFindInteresting(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        try {
            long limit = ListQuery.pageArgument(args, "limit");
            FunctionManager fm = session.program().getFunctionManager();
            ReferenceManager refMgr = session.program().getReferenceManager();
            List<JsonObject> resultsList = new ArrayList<>();

            String[] suspiciousNames = {"password", "key", "encrypt", "decrypt", "crypt",
                "auth", "login", "admin", "secret"};

            FunctionIterator iter = fm.getFunctions(true);
            while (iter.hasNext()) {
                session.monitor().checkCancelled();
                Function func = iter.next();
                String funcName = func.getName();
                Address funcAddr = func.getEntryPoint();
                long funcSize = func.getBody().getNumAddresses();

                int xrefCount = 0;
                for (Reference ref : refMgr.getReferencesTo(funcAddr)) {
                    session.monitor().checkCancelled();
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
            session.monitor().checkCancelled();
            resultsList.sort((a, b) -> b.getAsJsonArray("reasons").size() - a.getAsJsonArray("reasons").size());

            JsonArray results = new JsonArray();
            for (JsonObject item : resultsList) {
                session.monitor().checkCancelled();
                if (limit > 0 && results.size() >= limit) break;
                results.add(item);
            }

            JsonObject result = new JsonObject();
            result.add("results", results);
            result.addProperty("count", results.size());
            return result;
        } catch (Exception e) {
            return errorResult("Failed to find interesting functions: " + e.getMessage());
        }
    }
}
