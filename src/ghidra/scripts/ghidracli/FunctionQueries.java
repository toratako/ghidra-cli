package ghidracli;

import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;

final class FunctionQueries {
    private final ProgramSession session;
    private final AddressResolver addressResolver;

    FunctionQueries(ProgramSession session, AddressResolver addressResolver) {
        this.session = session;
        this.addressResolver = addressResolver;
    }

    JsonObject functionContext(Function func) {
        JsonObject funcData = new JsonObject();
        funcData.addProperty("name", func.getName());
        funcData.addProperty("address", AddressCodec.format(func.getEntryPoint()));
        funcData.addProperty("is_external", func.isExternal());
        var block = session.program().getMemory().getBlock(func.getEntryPoint());
        funcData.add("entry_memory", block == null ? JsonNull.INSTANCE : MemoryBlockInfo.summary(block));
        return funcData;
    }

    JsonObject functionToJson(Function func) {
        JsonObject funcData = functionContext(func);
        funcData.addProperty("size", func.getBody().getNumAddresses());
        funcData.addProperty("entry_point", AddressCodec.format(func.getEntryPoint()));
        funcData.add("tags", TagSupport.functionTagNames(func));

        String sig = null;
        try {
            sig = func.getPrototypeString(false, false);
        } catch (Exception e) {
            // ignore
        }
        if (sig != null) {
            funcData.addProperty("signature", sig);
        } else {
            funcData.add("signature", JsonNull.INSTANCE);
        }

        funcData.addProperty("calling_convention", func.getCallingConventionName());
        funcData.addProperty("no_return", func.hasNoReturn());
        funcData.add("stack_purge", stackPurgeToJson(func));

        String comment = func.getComment();
        if (comment != null) {
            funcData.addProperty("comment", comment);
        } else {
            funcData.add("comment", JsonNull.INSTANCE);
        }

        return funcData;
    }

    JsonObject stackPurgeToJson(Function func) {
        int bytes = func.getStackPurgeSize();
        JsonObject result = new JsonObject();
        if (bytes == Function.UNKNOWN_STACK_DEPTH_CHANGE) {
            result.addProperty("state", "unknown");
            result.add("bytes", JsonNull.INSTANCE);
        } else if (!func.isStackPurgeSizeValid()) {
            result.addProperty("state", "invalid");
            result.add("bytes", JsonNull.INSTANCE);
        } else {
            result.addProperty("state", "known");
            result.addProperty("bytes", bytes);
        }
        return result;
    }

    JsonObject functionDetailToJson(Function func) throws ghidra.util.exception.CancelledException {
        JsonObject result = functionToJson(func);
        JsonArray ranges = new JsonArray();
        for (var range : func.getBody().getAddressRanges()) {
            session.monitor().checkCancelled();
            JsonObject row = new JsonObject();
            row.addProperty("start", AddressCodec.format(range.getMinAddress()));
            row.addProperty("end", AddressCodec.format(range.getMaxAddress()));
            ranges.add(row);
        }
        result.add("body_ranges", ranges);
        return result;
    }

    String buildFunctionTargetHint(String target) {
        if (session.program() == null || target == null || target.isEmpty()) {
            return "Function not found";
        }

        String query = target.toLowerCase();
        List<String> containsMatches = new ArrayList<>();
        List<String> fuzzyMatches = new ArrayList<>();
        FunctionIterator iter = session.program().getFunctionManager().getFunctions(true);

        while (iter.hasNext()) {
            Function func = iter.next();
            String name = func.getName();
            String lname = name.toLowerCase();

            if (lname.contains(query)) {
                containsMatches.add(name);
            } else if (query.length() >= 3 && NameSuggestions.levenshteinDistance(lname, query) <= 3) {
                fuzzyMatches.add(name);
            }
        }

        Collections.sort(containsMatches);
        Collections.sort(fuzzyMatches);

        List<String> suggestions = new ArrayList<>();
        for (String name : containsMatches) {
            suggestions.add(name);
            if (suggestions.size() >= 5) break;
        }
        if (suggestions.size() < 5) {
            for (String name : fuzzyMatches) {
                if (!suggestions.contains(name)) suggestions.add(name);
                if (suggestions.size() >= 5) break;
            }
        }

        StringBuilder hint = new StringBuilder();
        hint.append("Cannot resolve function target: ").append(target)
            .append(". Try: ghidra-cli function list --help");
        if (!suggestions.isEmpty()) {
            hint.append(". Closest matches: ").append(String.join(", ", suggestions));
        }
        return hint.toString();
    }

    Function findFunctionByNameOrAddress(String nameOrAddr) {
        if (session.program() == null || nameOrAddr == null || nameOrAddr.isEmpty()) {
            return null;
        }

        FunctionManager fm = session.program().getFunctionManager();

        Address explicit = addressResolver.parseAddress(nameOrAddr);
        if (explicit != null) return fm.getFunctionContaining(explicit);

        Map<Address, Function> candidates = new LinkedHashMap<>();
        for (Address address : addressResolver.namedAddresses(nameOrAddr.trim())) {
            Function function = fm.getFunctionContaining(address);
            if (function != null) candidates.put(function.getEntryPoint(), function);
        }
        if (candidates.size() > 1) {
            throw new IllegalArgumentException("Ambiguous function target '" + nameOrAddr
                + "' at " + candidates.keySet().stream().map(AddressCodec::format).toList()
                + "; use a 0x-prefixed address");
        }
        return candidates.isEmpty() ? null : candidates.values().iterator().next();
    }
}
