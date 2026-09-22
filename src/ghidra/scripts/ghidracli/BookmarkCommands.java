package ghidracli;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.util.exception.CancelledException;
import java.util.Iterator;
import static ghidracli.JsonProtocol.errorResult;
import static ghidracli.JsonProtocol.getArgString;

final class BookmarkCommands {
    private final ProgramSession session;

    BookmarkCommands(ProgramSession session) {
        this.session = session;
    }

    JsonObject handleList() throws CancelledException {
        if (session.program() == null) return errorResult("No program loaded");

        JsonArray bookmarks = new JsonArray();
        Iterator<Bookmark> iterator = session.program().getBookmarkManager().getBookmarksIterator();
        while (iterator.hasNext()) {
            session.monitor().checkCancelled();
            bookmarks.add(toJson(iterator.next()));
        }
        return result(bookmarks);
    }

    JsonObject handleGet(JsonObject args) throws CancelledException {
        if (session.program() == null) return errorResult("No program loaded");

        String addressText = getArgString(args, "address");
        if (addressText == null) return errorResult("Address required");
        Address address = AddressCodec.parse(session.program().getAddressFactory(), addressText);
        if (address == null) return errorResult("Invalid address: " + addressText);

        JsonArray bookmarks = new JsonArray();
        for (Bookmark bookmark : session.program().getBookmarkManager().getBookmarks(address)) {
            session.monitor().checkCancelled();
            bookmarks.add(toJson(bookmark));
        }
        return result(bookmarks);
    }

    JsonObject handleSet(JsonObject args) throws CancelledException {
        if (session.program() == null) return errorResult("No program loaded");

        String addressText = getArgString(args, "address");
        String type = getArgString(args, "type");
        String category = getArgString(args, "category");
        String text = getArgString(args, "text");
        if (addressText == null) return errorResult("Address required");
        if (category == null) return errorResult("Bookmark category required");
        if (text == null) return errorResult("Bookmark text required");
        if (type == null) type = BookmarkType.NOTE;

        Address address = AddressCodec.parse(session.program().getAddressFactory(), addressText);
        if (address == null) return errorResult("Invalid address: " + addressText);
        session.monitor().checkCancelled();
        Bookmark bookmark = session.program().getBookmarkManager()
            .setBookmark(address, type, category, text);
        if (bookmark == null) return errorResult("Failed to set bookmark");

        JsonObject result = toJson(bookmark);
        result.addProperty("status", "set");
        return result;
    }

    JsonObject handleDelete(JsonObject args) throws CancelledException {
        if (session.program() == null) return errorResult("No program loaded");

        String addressText = getArgString(args, "address");
        String type = getArgString(args, "type");
        String category = getArgString(args, "category");
        if (addressText == null) return errorResult("Address required");
        if (category == null) return errorResult("Bookmark category required");
        if (type == null) type = BookmarkType.NOTE;

        Address address = AddressCodec.parse(session.program().getAddressFactory(), addressText);
        if (address == null) return errorResult("Invalid address: " + addressText);
        BookmarkManager bookmarks = session.program().getBookmarkManager();
        Bookmark bookmark = bookmarks.getBookmark(address, type, category);
        session.monitor().checkCancelled();
        if (bookmark != null) {
            bookmarks.removeBookmark(bookmark);
            if (bookmarks.getBookmark(address, type, category) != null)
                return errorResult("Failed to delete bookmark");
        }

        JsonObject result = new JsonObject();
        result.addProperty("status", "deleted");
        result.addProperty("address", AddressCodec.format(address));
        result.addProperty("type", type);
        result.addProperty("category", category);
        result.addProperty("deleted", bookmark == null ? 0 : 1);
        return result;
    }

    private static JsonObject toJson(Bookmark bookmark) {
        JsonObject row = new JsonObject();
        row.addProperty("address", AddressCodec.format(bookmark.getAddress()));
        row.addProperty("type", bookmark.getTypeString());
        row.addProperty("category", bookmark.getCategory());
        row.addProperty("comment", bookmark.getComment());
        return row;
    }

    private static JsonObject result(JsonArray bookmarks) {
        JsonObject result = new JsonObject();
        result.add("bookmarks", bookmarks);
        result.addProperty("count", bookmarks.size());
        return result;
    }
}
