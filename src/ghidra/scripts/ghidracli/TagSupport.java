package ghidracli;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionTag;
import ghidra.program.model.listing.FunctionTagManager;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

final class TagSupport {
    static final Comparator<FunctionTag> TAG_NAME_ORDER =
        Comparator.comparing(FunctionTag::getName);

    static JsonObject tagToJson(FunctionTag tag, FunctionTagManager tm) {
        JsonObject o = new JsonObject();
        o.addProperty("name", tag.getName());
        o.addProperty("comment", tag.getComment());
        o.addProperty("use_count", tm.getUseCount(tag));
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
