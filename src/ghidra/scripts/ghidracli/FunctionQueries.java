package ghidracli;

import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

final class FunctionQueries {
    private final ProgramSession session;
    private final AddressResolver addressResolver;

    FunctionQueries(ProgramSession session, AddressResolver addressResolver) {
        this.session = session;
        this.addressResolver = addressResolver;
    }

    JsonObject functionToJson(Function func) {
        JsonObject funcData = new JsonObject();
        funcData.addProperty("name", func.getName());
        funcData.addProperty("address", func.getEntryPoint().toString());
        funcData.addProperty("size", func.getBody().getNumAddresses());
        funcData.addProperty("entry_point", func.getEntryPoint().toString());
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

        String comment = func.getComment();
        if (comment != null) {
            funcData.addProperty("comment", comment);
        } else {
            funcData.add("comment", JsonNull.INSTANCE);
        }

        return funcData;
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
            .append(". Try: ghidra function list --filter ").append(target);
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

        // Resolve addresses, symbols, and auto names like FUN_00401234.
        Address addr = addressResolver.resolveAddress(nameOrAddr);
        if (addr != null) {
            Function f = fm.getFunctionContaining(addr);
            if (f != null) {
                return f;
            }
        }

        // Try as name
        FunctionIterator iter = fm.getFunctions(true);
        while (iter.hasNext()) {
            Function func = iter.next();
            if (func.getName().equals(nameOrAddr)) return func;
        }
        return null;
    }
}
