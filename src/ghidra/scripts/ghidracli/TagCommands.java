package ghidracli;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionTag;
import ghidra.program.model.listing.FunctionTagManager;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import static ghidracli.JsonProtocol.errorResult;
import static ghidracli.JsonProtocol.getArgBool;
import static ghidracli.JsonProtocol.getArgInt;
import static ghidracli.JsonProtocol.getArgString;
import static ghidracli.JsonProtocol.getArgStringArray;

final class TagCommands {
    private final ProgramSession session;
    private final FunctionQueries functionQueries;

    TagCommands(ProgramSession session, FunctionQueries functionQueries) {
        this.session = session;
        this.functionQueries = functionQueries;
    }

    JsonObject handleTagList(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");
        int limit = getArgInt(args, "limit", 0);
        String funcTarget = getArgString(args, "function");
        FunctionTagManager tm = session.program().getFunctionManager().getFunctionTagManager();

        List<FunctionTag> all;
        if (funcTarget != null) {
            Function func = functionQueries.findFunctionByNameOrAddress(funcTarget);
            if (func == null) return errorResult(functionQueries.buildFunctionTargetHint(funcTarget));
            all = new ArrayList<>(func.getTags());          // copy the live set
        } else {
            // getAllFunctionTags() returns DB record (creation) order — not sorted.
            all = new ArrayList<>(tm.getAllFunctionTags());
        }
        // Sort BEFORE applying limit, or --limit N truncates by creation order.
        all.sort(TagSupport.TAG_NAME_ORDER);

        JsonArray tags = new JsonArray();
        for (FunctionTag t : all) {
            if (limit > 0 && tags.size() >= limit) break;
            tags.add(TagSupport.tagToJson(t, tm));
        }
        JsonObject result = new JsonObject();
        result.add("tags", tags);
        result.addProperty("count", tags.size());
        return result;
    }

    JsonObject handleTagGet(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");
        String name = getArgString(args, "name");
        if (name == null || name.isEmpty()) return errorResult("Tag name required");
        int limit = getArgInt(args, "limit", 0);

        FunctionTagManager tm = session.program().getFunctionManager().getFunctionTagManager();
        FunctionTag tag = tm.getFunctionTag(name);
        if (tag == null) return errorResult(TagSupport.tagNotFoundError(name, tm));

        JsonArray functions = new JsonArray();
        if (tm.getUseCount(tag) > 0) {
            // No public reverse index in Ghidra; linear scan like Ghidra's own
            // Function Tags window. Non-external functions only (§7a policy).
            FunctionIterator iter = session.program().getFunctionManager().getFunctions(true);
            while (iter.hasNext()) {
                if (limit > 0 && functions.size() >= limit) break;
                Function func = iter.next();
                if (func.getTags().contains(tag)) {
                    JsonObject o = new JsonObject();
                    o.addProperty("name", func.getName());
                    o.addProperty("address", func.getEntryPoint().toString());
                    functions.add(o);
                }
            }
        }
        // Envelope constraint: "target"/"count" are META_KEYS on the Rust side,
        // so this unwraps to member-function rows. Do not add non-meta keys
        // (comment/use_count live in tag_list).
        JsonObject result = new JsonObject();
        result.addProperty("target", name);
        result.add("functions", functions);
        result.addProperty("count", functions.size());
        return result;
    }

    JsonObject handleTagCreate(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");
        String name = getArgString(args, "name");
        String comment = getArgString(args, "comment");
        if (name == null) return errorResult("Tag name required");

        try {
            FunctionTagManager tm = session.program().getFunctionManager().getFunctionTagManager();
            FunctionTag existing = tm.getFunctionTag(name);
            if (existing != null) {
                JsonObject result = new JsonObject();
                result.addProperty("status", "created");
                result.addProperty("name", existing.getName());
                result.addProperty("comment", existing.getComment());
                result.addProperty("existed", true);
                return result;
            }

            String err = TagSupport.validateTagName(name);
            if (err != null) return errorResult(err);

            ProgramTransaction transaction = session.transaction("Create function tag");
            FunctionTag tag;
            try {
                tag = tm.createFunctionTag(name, comment == null ? "" : comment);
                transaction.end(true);
            } catch (Exception e) {
                transaction.end(false);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "created");
            result.addProperty("name", tag.getName());
            result.addProperty("comment", tag.getComment());
            result.addProperty("existed", false);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to create tag: " + e.getMessage());
        }
    }

    JsonObject handleTagDelete(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");
        String name = getArgString(args, "name");
        if (name == null || name.isEmpty()) return errorResult("Tag name required");

        try {
            FunctionTagManager tm = session.program().getFunctionManager().getFunctionTagManager();
            FunctionTag tag = tm.getFunctionTag(name);
            if (tag == null) return errorResult(TagSupport.tagNotFoundError(name, tm));

            // Capture BOTH counts before delete: use_count is Ghidra's raw number
            // (may include external functions); functions_affected is the
            // non-external membership consistent with what `tag get` shows.
            int useCount = tm.getUseCount(tag);
            int functionsAffected = 0;
            if (useCount > 0) {
                FunctionIterator iter = session.program().getFunctionManager().getFunctions(true);
                while (iter.hasNext()) {
                    if (iter.next().getTags().contains(tag)) functionsAffected++;
                }
            }

            ProgramTransaction transaction = session.transaction("Delete function tag");
            try {
                tag.delete();                 // global: detaches from ALL functions
                transaction.end(true);
            } catch (Exception e) {
                transaction.end(false);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "deleted");
            result.addProperty("name", name);
            result.addProperty("use_count", useCount);
            result.addProperty("functions_affected", functionsAffected);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to delete tag: " + e.getMessage());
        }
    }

    JsonObject handleTagRename(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");
        String name = getArgString(args, "name");
        String newName = getArgString(args, "new_name");
        if (name == null || newName == null || name.isEmpty())
            return errorResult("name and new_name required");

        try {
            FunctionTagManager tm = session.program().getFunctionManager().getFunctionTagManager();
            FunctionTag tag = tm.getFunctionTag(name);
            if (tag == null) return errorResult(TagSupport.tagNotFoundError(name, tm));
            if (tm.getFunctionTag(newName) != null)
                return errorResult("Tag already exists: '" + newName + "'");

            String err = TagSupport.validateTagName(newName);
            if (err != null) return errorResult(err);

            int useCount = tm.getUseCount(tag);
            ProgramTransaction transaction = session.transaction("Rename function tag");
            try {
                tag.setName(newName);         // global rename; functions store the id
                transaction.end(true);
            } catch (Exception e) {
                transaction.end(false);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "renamed");
            result.addProperty("old_name", name);
            result.addProperty("new_name", newName);
            result.addProperty("use_count", useCount);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to rename tag: " + e.getMessage());
        }
    }

    JsonObject handleTagSetComment(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");
        String name = getArgString(args, "name");
        String comment = getArgString(args, "comment");
        if (name == null || name.isEmpty()) return errorResult("Tag name required");

        try {
            FunctionTagManager tm = session.program().getFunctionManager().getFunctionTagManager();
            FunctionTag tag = tm.getFunctionTag(name);
            if (tag == null) return errorResult(TagSupport.tagNotFoundError(name, tm));

            ProgramTransaction transaction = session.transaction("Set function tag comment");
            try {
                tag.setComment(comment == null ? "" : comment);
                transaction.end(true);
            } catch (Exception e) {
                transaction.end(false);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "comment_set");
            result.addProperty("name", name);
            result.addProperty("comment", comment == null ? "" : comment);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to set tag comment: " + e.getMessage());
        }
    }

    JsonObject handleTagAdd(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");
        String target = getArgString(args, "function");
        String[] rawTags = getArgStringArray(args, "tags");
        boolean noCreate = getArgBool(args, "no_create", false);
        if (target == null || rawTags.length == 0)
            return errorResult("function and tags are required");

        try {
            // Dedupe argv up front: `tag add f crypto crypto` must not double-report.
            LinkedHashSet<String> tagNames = new LinkedHashSet<>(Arrays.asList(rawTags));
            Function func = functionQueries.findFunctionByNameOrAddress(target);
            if (func == null) return errorResult(functionQueries.buildFunctionTargetHint(target));

            FunctionTagManager tm = session.program().getFunctionManager().getFunctionTagManager();
            Set<String> current = new HashSet<>();
            for (FunctionTag t : func.getTags()) current.add(t.getName());

            List<String> toCreate = new ArrayList<>();
            for (String name : tagNames) {
                if (tm.getFunctionTag(name) != null) continue;  // existing: any name attachable
                String err = TagSupport.validateTagName(name);             // validate only names we'd CREATE
                if (err != null) return errorResult(err);
                toCreate.add(name);
            }
            if (noCreate && !toCreate.isEmpty())
                return errorResult("Tags do not exist (--no-create): " + String.join(", ", toCreate));

            JsonArray added = new JsonArray(), created = new JsonArray(), already = new JsonArray();
            ProgramTransaction transaction = session.transaction("Add function tags");
            try {
                for (String name : tagNames) {
                    if (current.contains(name)) { already.add(name); continue; }
                    func.addTag(name);   // auto-creates; returns true unconditionally
                    added.add(name);
                    if (toCreate.contains(name)) created.add(name);
                }
                transaction.end(true);
            } catch (Exception e) {
                transaction.end(false);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "tagged");
            result.addProperty("function", func.getName());
            result.addProperty("address", func.getEntryPoint().toString());
            result.add("added", added);
            result.add("created", created);
            result.add("already_present", already);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to add tags: " + e.getMessage());
        }
    }

    JsonObject handleTagRemove(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");
        String target = getArgString(args, "function");
        String[] rawTags = getArgStringArray(args, "tags");
        boolean all = getArgBool(args, "all", false);
        if (target == null || (rawTags.length == 0 && !all))
            return errorResult("function and tags (or all) are required");

        try {
            Function func = functionQueries.findFunctionByNameOrAddress(target);
            if (func == null) return errorResult(functionQueries.buildFunctionTargetHint(target));

            // Pre-read into a COPY: getTags() is the live set and removeTag
            // mutates it — iterating it directly while removing throws CME.
            List<String> currentNames = new ArrayList<>();
            for (FunctionTag t : func.getTags()) currentNames.add(t.getName());
            Set<String> current = new HashSet<>(currentNames);

            LinkedHashSet<String> tagNames = all
                ? new LinkedHashSet<>(currentNames)
                : new LinkedHashSet<>(Arrays.asList(rawTags));

            JsonArray removed = new JsonArray(), notPresent = new JsonArray();
            ProgramTransaction transaction = session.transaction("Remove function tags");
            try {
                for (String name : tagNames) {
                    if (current.contains(name)) {
                        func.removeTag(name);   // void; silent — membership pre-checked
                        removed.add(name);
                    } else {
                        notPresent.add(name);
                    }
                }
                transaction.end(true);
            } catch (Exception e) {
                transaction.end(false);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "untagged");
            result.addProperty("function", func.getName());
            result.addProperty("address", func.getEntryPoint().toString());
            result.add("removed", removed);
            result.add("not_present", notPresent);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to remove tags: " + e.getMessage());
        }
    }
    JsonObject handleFunctionTagAdd(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");
        String target = getArgString(args, "target");
        String tagName = getArgString(args, "tag_name");
        if (target == null || target.isEmpty()) return errorResult("target required");
        if (tagName == null || tagName.isEmpty()) return errorResult("tag_name required");

        try {
            Function func = functionQueries.findFunctionByNameOrAddress(target);
            if (func == null) return errorResult(functionQueries.buildFunctionTargetHint(target));

            ProgramTransaction transaction = session.transaction("Add function tag");
            try {
                func.addTag(tagName);
                transaction.end(true);
            } catch (Exception e) {
                transaction.end(true);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "tag_added");
            result.addProperty("function", func.getName());
            result.addProperty("address", func.getEntryPoint().toString());
            result.addProperty("tag", tagName);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to add tag: " + e.getMessage());
        }
    }

    JsonObject handleFunctionTagRemove(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");
        String target = getArgString(args, "target");
        String tagName = getArgString(args, "tag_name");
        if (target == null || target.isEmpty()) return errorResult("target required");
        if (tagName == null || tagName.isEmpty()) return errorResult("tag_name required");

        try {
            Function func = functionQueries.findFunctionByNameOrAddress(target);
            if (func == null) return errorResult(functionQueries.buildFunctionTargetHint(target));

            ProgramTransaction transaction = session.transaction("Remove function tag");
            try {
                func.removeTag(tagName);
                transaction.end(true);
            } catch (Exception e) {
                transaction.end(true);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "tag_removed");
            result.addProperty("function", func.getName());
            result.addProperty("address", func.getEntryPoint().toString());
            result.addProperty("tag", tagName);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to remove tag: " + e.getMessage());
        }
    }

    /** Tags on one function (target given), or every tag definition in the program (no target). */
    JsonObject handleFunctionTagList(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");
        String target = getArgString(args, "target");

        try {
            JsonObject result = new JsonObject();
            if (target != null && !target.isEmpty()) {
                Function func = functionQueries.findFunctionByNameOrAddress(target);
                if (func == null) return errorResult(functionQueries.buildFunctionTargetHint(target));

                JsonArray tags = new JsonArray();
                for (FunctionTag tag : func.getTags()) {
                    JsonObject t = new JsonObject();
                    t.addProperty("name", tag.getName());
                    t.addProperty("comment", tag.getComment());
                    tags.add(t);
                }
                result.addProperty("function", func.getName());
                result.addProperty("address", func.getEntryPoint().toString());
                result.add("tags", tags);
            } else {
                JsonArray tags = new JsonArray();
                FunctionTagManager tagManager = session.program().getFunctionManager().getFunctionTagManager();
                for (FunctionTag tag : tagManager.getAllFunctionTags()) {
                    JsonObject t = new JsonObject();
                    t.addProperty("name", tag.getName());
                    t.addProperty("comment", tag.getComment());
                    t.addProperty("use_count", tagManager.getUseCount(tag));
                    tags.add(t);
                }
                result.add("tags", tags);
            }
            return result;
        } catch (Exception e) {
            return errorResult("Failed to list tags: " + e.getMessage());
        }
    }
}
