package ghidracli.symbol;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;
import ghidracli.query.AddressCodec;
import ghidracli.query.ListQuery;
import ghidracli.session.ProgramSession;
import java.util.Locale;

import static ghidracli.protocol.JsonProtocol.errorResult;
import static ghidracli.protocol.JsonProtocol.getArgBool;
import static ghidracli.protocol.JsonProtocol.getArgString;

public final class CommentCommands {
    private final ProgramSession session;

    public CommentCommands(ProgramSession session) {
        this.session = session;
    }

    private int resolveCommentType(String typeStr) {
        switch (typeStr.toUpperCase(Locale.ROOT)) {
            case "EOL":   return CodeUnit.EOL_COMMENT;
            case "PRE":   return CodeUnit.PRE_COMMENT;
            case "POST":  return CodeUnit.POST_COMMENT;
            case "PLATE": return CodeUnit.PLATE_COMMENT;
            default: throw new IllegalArgumentException("Invalid comment type: " + typeStr
                + ". Must be one of: EOL, PRE, POST, PLATE");
        }
    }

    public JsonObject handleCommentList(JsonObject args) throws ghidra.util.exception.CancelledException {
        if (session.program() == null) return errorResult("No program loaded");

        ListQuery query = new ListQuery(session, args);

        Listing listing = session.program().getListing();
        JsonArray comments = new JsonArray();

        int[][] commentTypes = {
            {CodeUnit.EOL_COMMENT},
            {CodeUnit.PRE_COMMENT},
            {CodeUnit.POST_COMMENT},
            {CodeUnit.PLATE_COMMENT}
        };
        String[] commentNames = {"EOL", "PRE", "POST", "PLATE"};

        // Comments can belong to external functions or unmapped addresses too.
        // The comment adapter requires a non-null set, even for an unrestricted query.
        AddressSet addresses = new AddressSet();
        for (AddressSpace space : session.program().getAddressFactory().getAllAddressSpaces()) {
            if (space.isMemorySpace() || space.isExternalSpace()) {
                addresses.addRange(space.getMinAddress(), space.getMaxAddress());
            }
        }
        AddressIterator addrIter = listing.getCommentAddressIterator(addresses, true);
        while (addrIter.hasNext()) {
            if (query.isFull()) break;

            Address addr = addrIter.next();
            for (int i = 0; i < commentNames.length; i++) {
                if (query.isFull()) break;

                String text = listing.getComment(commentTypes[i][0], addr);
                if (text != null) {
                    if (!query.include(text)) {
                        continue;
                    }

                    JsonObject commentObj = new JsonObject();
                    commentObj.addProperty("address", AddressCodec.format(addr));
                    commentObj.addProperty("type", commentNames[i]);
                    commentObj.addProperty("text", text);
                    comments.add(commentObj);
                    query.record();
                }
            }
        }

        JsonObject result = new JsonObject();
        result.add("comments", comments);
        result.addProperty("count", comments.size());
        return result;
    }

    public JsonObject handleCommentGet(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String addressStr = getArgString(args, "address");
        if (addressStr == null) return errorResult("Address required");

        try {
            Address addr = AddressCodec.parse(session.program().getAddressFactory(), addressStr);
            if (addr == null) return errorResult("Invalid address: " + addressStr);

            Listing listing = session.program().getListing();

            int[] types = {CodeUnit.EOL_COMMENT, CodeUnit.PRE_COMMENT, CodeUnit.POST_COMMENT, CodeUnit.PLATE_COMMENT};
            String[] names = {"EOL", "PRE", "POST", "PLATE"};

            JsonArray comments = new JsonArray();
            for (int i = 0; i < types.length; i++) {
                String text = listing.getComment(types[i], addr);
                if (text != null) {
                    JsonObject commentObj = new JsonObject();
                    commentObj.addProperty("type", names[i]);
                    commentObj.addProperty("text", text);
                    comments.add(commentObj);
                }
            }

            JsonObject result = new JsonObject();
            result.addProperty("address", AddressCodec.format(addr));
            result.add("comments", comments);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to get comments: " + e.getMessage());
        }
    }

    public JsonObject handleCommentSet(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String addressStr = getArgString(args, "address");
        String text = getArgString(args, "text");
        String commentTypeStr = getArgString(args, "comment_type");
        if (commentTypeStr == null) commentTypeStr = "EOL";

        if (addressStr == null) return errorResult("Address required");

        try {
            Address addr = AddressCodec.parse(session.program().getAddressFactory(), addressStr);
            if (addr == null) return errorResult("Invalid address: " + addressStr);

            int commentType = resolveCommentType(commentTypeStr);
            Listing listing = session.program().getListing();

            listing.setComment(addr, commentType, text);

            JsonObject result = new JsonObject();
            result.addProperty("status", "set");
            result.addProperty("address", AddressCodec.format(addr));
            return result;
        } catch (Exception e) {
            return errorResult("Failed to set comment: " + e.getMessage());
        }
    }

    public JsonObject handleCommentDelete(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String addressStr = getArgString(args, "address");
        String commentTypeStr = getArgString(args, "comment_type");
        boolean all = getArgBool(args, "all", false);
        if (addressStr == null) return errorResult("Address required");
        if (all == (commentTypeStr != null)) {
            return errorResult("Specify exactly one of comment_type or all");
        }

        try {
            int[] types = all
                ? new int[] {CodeUnit.EOL_COMMENT, CodeUnit.PRE_COMMENT, CodeUnit.POST_COMMENT, CodeUnit.PLATE_COMMENT}
                : new int[] {resolveCommentType(commentTypeStr)};
            Address addr = AddressCodec.parse(session.program().getAddressFactory(), addressStr);
            if (addr == null) return errorResult("Invalid address: " + addressStr);

            Listing listing = session.program().getListing();

            for (int type : types) {
                listing.setComment(addr, type, null);
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "deleted");
            result.addProperty("address", AddressCodec.format(addr));
            return result;
        } catch (Exception e) {
            return errorResult("Failed to delete comment: " + e.getMessage());
        }
    }
}
