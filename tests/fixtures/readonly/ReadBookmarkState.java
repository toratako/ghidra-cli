import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import java.util.TreeMap;

public class ReadBookmarkState extends GhidraScript {
  public void run() {
    var sorted = new TreeMap<Long, JsonObject>();
    var bookmarks = currentProgram.getBookmarkManager().getBookmarksIterator();
    while (bookmarks.hasNext()) {
      var bookmark = bookmarks.next();
      var row = new JsonObject();
      row.addProperty("id", bookmark.getId());
      row.addProperty("address", bookmark.getAddress().toString());
      row.addProperty("type", bookmark.getTypeString());
      row.addProperty("category", bookmark.getCategory());
      row.addProperty("comment", bookmark.getComment());
      sorted.put(bookmark.getId(), row);
    }
    var rows = new JsonArray();
    sorted.values().forEach(rows::add);
    var result = new JsonObject();
    result.add("bookmarks", rows);
    result.addProperty("modification_number", currentProgram.getModificationNumber());
    writer.println(result);
  }
}
