package ghidracli;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import static ghidracli.JsonProtocol.errorResult;
import static ghidracli.JsonProtocol.getArgString;

final class CommentCommands {
    private final ProgramSession session;

    CommentCommands(ProgramSession session) {
        this.session = session;
    }

    private int resolveCommentType(String typeStr) {
        if (typeStr == null) return CodeUnit.EOL_COMMENT;
        switch (typeStr.toUpperCase()) {
            case "PRE":   return CodeUnit.PRE_COMMENT;
            case "POST":  return CodeUnit.POST_COMMENT;
            case "PLATE": return CodeUnit.PLATE_COMMENT;
            default:      return CodeUnit.EOL_COMMENT;
        }
    }

    JsonObject handleCommentList(JsonObject args) throws ghidra.util.exception.CancelledException {
        if (session.program() == null) return errorResult("No program loaded");

        ListQuery query = new ListQuery(session, args);

        Listing listing = session.program().getListing();
        Memory memory = session.program().getMemory();
        JsonArray comments = new JsonArray();

        int[][] commentTypes = {
            {CodeUnit.EOL_COMMENT},
            {CodeUnit.PRE_COMMENT},
            {CodeUnit.POST_COMMENT},
            {CodeUnit.PLATE_COMMENT}
        };
        String[] commentNames = {"EOL", "PRE", "POST", "PLATE"};

        for (MemoryBlock block : memory.getBlocks()) {
            if (query.isFull()) break;

            ghidra.program.model.address.AddressSet addrSet =
                new ghidra.program.model.address.AddressSet(block.getStart(), block.getEnd());

            ghidra.program.model.address.AddressIterator addrIter =
                listing.getCommentAddressIterator(addrSet, true);

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
                        commentObj.addProperty("address", addr.toString());
                        commentObj.addProperty("type", commentNames[i]);
                        commentObj.addProperty("text", text);
                        comments.add(commentObj);
                        query.record();
                    }
                }
            }
        }

        JsonObject result = new JsonObject();
        result.add("comments", comments);
        result.addProperty("count", comments.size());
        return result;
    }

    JsonObject handleCommentGet(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String addressStr = getArgString(args, "address");
        if (addressStr == null) return errorResult("Address required");

        try {
            Address addr = session.program().getAddressFactory().getAddress(addressStr);
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
            result.addProperty("address", addressStr);
            result.add("comments", comments);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to get comments: " + e.getMessage());
        }
    }

    JsonObject handleCommentSet(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String addressStr = getArgString(args, "address");
        String text = getArgString(args, "text");
        String commentTypeStr = getArgString(args, "comment_type");
        if (commentTypeStr == null) commentTypeStr = "EOL";

        if (addressStr == null) return errorResult("Address required");

        try {
            Address addr = session.program().getAddressFactory().getAddress(addressStr);
            if (addr == null) return errorResult("Invalid address: " + addressStr);

            Set<String> validTypes = new HashSet<>(Arrays.asList("EOL", "PRE", "POST", "PLATE"));
            if (!validTypes.contains(commentTypeStr.toUpperCase())) {
                return errorResult("Invalid comment type: " + commentTypeStr + ". Must be one of: EOL, PRE, POST, PLATE");
            }

            int commentType = resolveCommentType(commentTypeStr);
            Listing listing = session.program().getListing();

            ProgramTransaction transaction = session.transaction("Set comment");
            try {
                listing.setComment(addr, commentType, text);
                transaction.end(true);
            } catch (Exception e) {
                transaction.end(true);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "set");
            result.addProperty("address", addressStr);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to set comment: " + e.getMessage());
        }
    }

    JsonObject handleCommentDelete(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String addressStr = getArgString(args, "address");
        if (addressStr == null) return errorResult("Address required");

        try {
            Address addr = session.program().getAddressFactory().getAddress(addressStr);
            if (addr == null) return errorResult("Invalid address: " + addressStr);

            Listing listing = session.program().getListing();

            ProgramTransaction transaction = session.transaction("Delete comments");
            try {
                listing.setComment(addr, CodeUnit.EOL_COMMENT, null);
                listing.setComment(addr, CodeUnit.PRE_COMMENT, null);
                listing.setComment(addr, CodeUnit.POST_COMMENT, null);
                listing.setComment(addr, CodeUnit.PLATE_COMMENT, null);
                transaction.end(true);
            } catch (Exception e) {
                transaction.end(true);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "deleted");
            result.addProperty("address", addressStr);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to delete comment: " + e.getMessage());
        }
    }
}
