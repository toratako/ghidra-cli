package ghidracli.function;

import static ghidracli.protocol.JsonProtocol.errorResult;
import static ghidracli.protocol.JsonProtocol.getArgBool;
import static ghidracli.protocol.JsonProtocol.getArgString;
import static ghidracli.protocol.JsonProtocol.getArgStringArray;
import static ghidracli.protocol.JsonProtocol.getNonnegativeIntArg;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionTag;
import ghidra.program.model.listing.FunctionTagManager;
import ghidra.util.exception.CancelledException;
import ghidracli.query.AddressCodec;
import ghidracli.session.ProgramSession;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public final class TagCommands {
  private final ProgramSession session;
  private final FunctionQueries functionQueries;

  public TagCommands(ProgramSession session, FunctionQueries functionQueries) {
    this.session = session;
    this.functionQueries = functionQueries;
  }

  public JsonObject handleTagList(JsonObject args) throws CancelledException {
    if (session.program() == null) return errorResult("No program loaded");
    int limit = getNonnegativeIntArg(args, "limit", 0);
    String funcTarget = getArgString(args, "function");
    FunctionTagManager tm = session.program().getFunctionManager().getFunctionTagManager();

    List<FunctionTag> all;
    if (funcTarget != null) {
      Function func = functionQueries.findFunctionByNameOrAddress(funcTarget);
      if (func == null) return errorResult(functionQueries.buildFunctionTargetHint(funcTarget));
      all = new ArrayList<>(func.getTags()); // copy the live set
    } else {
      // getAllFunctionTags() returns DB record (creation) order — not sorted.
      all = new ArrayList<>(tm.getAllFunctionTags());
    }
    // Sort BEFORE applying limit, or --limit N truncates by creation order.
    all.sort(TagSupport.TAG_NAME_ORDER);

    var usage = TagSupport.tagUsage(session);
    JsonArray tags = new JsonArray();
    for (FunctionTag t : all) {
      session.monitor().checkCancelled();
      if (limit > 0 && tags.size() >= limit) break;
      tags.add(TagSupport.tagToJson(t, usage.getOrDefault(t.getId(), TagSupport.TagUsage.NONE)));
    }
    JsonObject result = new JsonObject();
    result.add("tags", tags);
    result.addProperty("count", tags.size());
    return result;
  }

  public JsonObject handleTagGet(JsonObject args) throws CancelledException {
    if (session.program() == null) return errorResult("No program loaded");
    String name = getArgString(args, "name");
    if (name == null || name.isEmpty()) return errorResult("Tag name required");

    FunctionTagManager tm = session.program().getFunctionManager().getFunctionTagManager();
    FunctionTag tag = tm.getFunctionTag(name);
    if (tag == null) return errorResult(TagSupport.tagNotFoundError(name, tm, session.monitor()));

    var usage = TagSupport.tagUsage(session);
    return TagSupport.tagToJson(tag, usage.getOrDefault(tag.getId(), TagSupport.TagUsage.NONE));
  }

  public JsonObject handleTagCreate(JsonObject args) {
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

      FunctionTag tag = tm.createFunctionTag(name, comment == null ? "" : comment);

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

  public JsonObject handleTagDelete(JsonObject args) {
    if (session.program() == null) return errorResult("No program loaded");
    String name = getArgString(args, "name");
    if (name == null || name.isEmpty()) return errorResult("Tag name required");

    try {
      FunctionTagManager tm = session.program().getFunctionManager().getFunctionTagManager();
      FunctionTag tag = tm.getFunctionTag(name);
      if (tag == null) return errorResult(TagSupport.tagNotFoundError(name, tm, session.monitor()));

      // Capture total usage, including external functions, and mapped
      // membership consistent with `function list --tag` in one scan.
      var usage = TagSupport.tagUsage(session).getOrDefault(tag.getId(), TagSupport.TagUsage.NONE);

      tag.delete(); // global: detaches from ALL functions

      JsonObject result = new JsonObject();
      result.addProperty("status", "deleted");
      result.addProperty("name", name);
      result.addProperty("use_count", usage.useCount());
      result.addProperty("functions_affected", usage.functionsAffected());
      return result;
    } catch (Exception e) {
      return errorResult("Failed to delete tag: " + e.getMessage());
    }
  }

  public JsonObject handleTagRename(JsonObject args) {
    if (session.program() == null) return errorResult("No program loaded");
    String name = getArgString(args, "name");
    String newName = getArgString(args, "new_name");
    if (name == null || newName == null || name.isEmpty())
      return errorResult("name and new_name required");

    try {
      FunctionTagManager tm = session.program().getFunctionManager().getFunctionTagManager();
      FunctionTag tag = tm.getFunctionTag(name);
      if (tag == null) return errorResult(TagSupport.tagNotFoundError(name, tm, session.monitor()));
      if (tm.getFunctionTag(newName) != null)
        return errorResult("Tag already exists: '" + newName + "'");

      String err = TagSupport.validateTagName(newName);
      if (err != null) return errorResult(err);

      var usage = TagSupport.tagUsage(session).getOrDefault(tag.getId(), TagSupport.TagUsage.NONE);
      tag.setName(newName); // global rename; functions store the id

      JsonObject result = new JsonObject();
      result.addProperty("status", "renamed");
      result.addProperty("old_name", name);
      result.addProperty("new_name", newName);
      result.addProperty("use_count", usage.useCount());
      return result;
    } catch (Exception e) {
      return errorResult("Failed to rename tag: " + e.getMessage());
    }
  }

  public JsonObject handleTagSetComment(JsonObject args) {
    if (session.program() == null) return errorResult("No program loaded");
    String name = getArgString(args, "name");
    String comment = getArgString(args, "comment");
    if (name == null || name.isEmpty()) return errorResult("Tag name required");

    try {
      FunctionTagManager tm = session.program().getFunctionManager().getFunctionTagManager();
      FunctionTag tag = tm.getFunctionTag(name);
      if (tag == null) return errorResult(TagSupport.tagNotFoundError(name, tm, session.monitor()));

      tag.setComment(comment == null ? "" : comment);

      JsonObject result = new JsonObject();
      result.addProperty("status", "comment_set");
      result.addProperty("name", name);
      result.addProperty("comment", comment == null ? "" : comment);
      return result;
    } catch (Exception e) {
      return errorResult("Failed to set tag comment: " + e.getMessage());
    }
  }

  public JsonObject handleTagAttach(JsonObject args) {
    if (session.program() == null) return errorResult("No program loaded");
    String target = getArgString(args, "function");
    String[] rawTags = getArgStringArray(args, "tags");
    if (target == null || rawTags.length == 0) return errorResult("function and tags are required");

    try {
      // Dedupe argv up front: repeated names must not double-report.
      LinkedHashSet<String> tagNames = new LinkedHashSet<>(Arrays.asList(rawTags));
      Function func = functionQueries.findFunctionByNameOrAddress(target);
      if (func == null) return errorResult(functionQueries.buildFunctionTargetHint(target));

      FunctionTagManager tm = session.program().getFunctionManager().getFunctionTagManager();
      for (String name : tagNames) {
        session.monitor().checkCancelled();
        if (tm.getFunctionTag(name) == null)
          return errorResult(TagSupport.tagNotFoundError(name, tm, session.monitor()));
      }
      Set<String> current = new HashSet<>();
      for (FunctionTag t : func.getTags()) current.add(t.getName());

      JsonArray attached = new JsonArray(), already = new JsonArray();
      for (String name : tagNames) {
        session.monitor().checkCancelled();
        if (current.contains(name)) {
          already.add(name);
          continue;
        }
        if (!func.addTag(name)) {
          return errorResult("Failed to attach tag '" + name + "' to function " + func.getName());
        }
        attached.add(name);
      }

      JsonObject result = new JsonObject();
      result.addProperty("status", "attached");
      result.addProperty("function", func.getName());
      result.addProperty("address", AddressCodec.format(func.getEntryPoint()));
      result.add("attached", attached);
      result.add("already_present", already);
      return result;
    } catch (Exception e) {
      return errorResult("Failed to attach tags: " + e.getMessage());
    }
  }

  public JsonObject handleTagDetach(JsonObject args) {
    if (session.program() == null) return errorResult("No program loaded");
    String target = getArgString(args, "function");
    String[] rawTags = getArgStringArray(args, "tags");
    boolean all = getArgBool(args, "all", false);
    if (target == null || (rawTags.length == 0 && !all))
      return errorResult("function and tags (or all) are required");
    if (all && rawTags.length > 0) return errorResult("Specify exactly one of tags or all");

    try {
      Function func = functionQueries.findFunctionByNameOrAddress(target);
      if (func == null) return errorResult(functionQueries.buildFunctionTargetHint(target));

      // Pre-read into a COPY: getTags() is the live set and removeTag
      // mutates it — iterating it directly while removing throws CME.
      List<String> currentNames = new ArrayList<>();
      for (FunctionTag t : func.getTags()) currentNames.add(t.getName());
      Set<String> current = new HashSet<>(currentNames);

      LinkedHashSet<String> tagNames =
          all ? new LinkedHashSet<>(currentNames) : new LinkedHashSet<>(Arrays.asList(rawTags));

      FunctionTagManager tm = session.program().getFunctionManager().getFunctionTagManager();
      for (String name : tagNames) {
        session.monitor().checkCancelled();
        if (tm.getFunctionTag(name) == null)
          return errorResult(TagSupport.tagNotFoundError(name, tm, session.monitor()));
      }

      JsonArray detached = new JsonArray(), notPresent = new JsonArray();
      for (String name : tagNames) {
        session.monitor().checkCancelled();
        if (current.contains(name)) {
          func.removeTag(name); // void; silent — membership pre-checked
          detached.add(name);
        } else {
          notPresent.add(name);
        }
      }

      JsonObject result = new JsonObject();
      result.addProperty("status", "detached");
      result.addProperty("function", func.getName());
      result.addProperty("address", AddressCodec.format(func.getEntryPoint()));
      result.add("detached", detached);
      result.add("not_present", notPresent);
      return result;
    } catch (Exception e) {
      return errorResult("Failed to detach tags: " + e.getMessage());
    }
  }
}
