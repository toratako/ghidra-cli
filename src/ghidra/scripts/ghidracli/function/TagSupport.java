package ghidracli.function;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionTag;
import ghidra.program.model.listing.FunctionTagManager;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.CancelledException;
import ghidracli.query.NameSuggestions;
import ghidracli.session.ProgramSession;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

final class TagSupport {
    static final Comparator<FunctionTag> TAG_NAME_ORDER =
        Comparator.comparing(FunctionTag::getName);

    record TagUsage(int useCount, int functionsAffected) {
        static final TagUsage NONE = new TagUsage(0, 0);
    }

    static Map<Long, TagUsage> tagUsage(ProgramSession session) throws CancelledException {
        Map<Long, TagUsage> counts = new HashMap<>();
        var program = session.program();
        var functions = program.getFunctionManager();
        // Native use-count caches key on mutable tag names/comments. Count stable
        // IDs from memberships so metadata edits cannot lose or negate usage.
        // A null symbol address set includes external and unmapped functions.
        var symbols = program.getSymbolTable().getSymbols(null, SymbolType.FUNCTION, true);
        while (symbols.hasNext()) {
            session.monitor().checkCancelled();
            Function function = functions.getFunction(symbols.next().getID());
            boolean listed = program.getMemory().contains(function.getEntryPoint());
            for (FunctionTag tag : function.getTags()) {
                session.monitor().checkCancelled();
                TagUsage before = counts.getOrDefault(tag.getId(), TagUsage.NONE);
                counts.put(tag.getId(), new TagUsage(before.useCount() + 1,
                    before.functionsAffected() + (listed ? 1 : 0)));
            }
        }
        session.monitor().checkCancelled();
        return counts;
    }

    static JsonObject tagToJson(FunctionTag tag, TagUsage usage) {
        JsonObject o = new JsonObject();
        o.addProperty("name", tag.getName());
        o.addProperty("comment", tag.getComment());
        o.addProperty("use_count", usage.useCount());
        return o;
    }

    static JsonArray functionTagNames(Function func) {
        List<String> names = new ArrayList<>();
        for (FunctionTag t : func.getTags()) names.add(t.getName());
        Collections.sort(names);
        JsonArray arr = new JsonArray();
        for (String n : names) arr.add(n);
        return arr;
    }

    static String validateTagName(String name) {
        if (name == null || name.trim().isEmpty()) return "Tag name cannot be empty";
        if (name.contains(",")) return "Tag name cannot contain ',' (Ghidra GUI tag separator): " + name;
        if (name.contains(";")) return "Tag name cannot contain ';' (CSV array separator): " + name;
        return null;
    }

    static String tagNotFoundError(String name, FunctionTagManager tm) {
        StringBuilder msg = new StringBuilder("No tag named '").append(name).append("'");
        List<String> near = new ArrayList<>();
        for (FunctionTag t : tm.getAllFunctionTags()) {
            if (t.getName().equalsIgnoreCase(name) && !t.getName().equals(name)) {
                near.add(t.getName());
            }
        }
        if (near.isEmpty() && name.length() >= 3) {
            for (FunctionTag t : tm.getAllFunctionTags()) {
                if (NameSuggestions.levenshteinDistance(t.getName().toLowerCase(), name.toLowerCase()) <= 2) {
                    near.add(t.getName());
                }
            }
        }
        if (!near.isEmpty()) {
            Collections.sort(near);
            msg.append(". Did you mean '").append(near.get(0)).append("'?");
        }
        return msg.toString();
    }
}
