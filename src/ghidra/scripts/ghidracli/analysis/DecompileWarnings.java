package ghidracli.analysis;

import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import ghidra.app.decompiler.ClangBreak;
import ghidra.app.decompiler.ClangCommentToken;
import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidracli.query.AddressCodec;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/** Diagnostics from a completed decompilation, without changing its C text. */
final class DecompileWarnings {
    private static final Pattern WARNING_PREFIX =
        Pattern.compile("^(?:WARNING(?: \\([^\\r\\n)]*\\))?|DISPLAY WARNING):");

    private DecompileWarnings() {}

    static JsonArray collect(DecompileResults results) {
        JsonArray warnings = new JsonArray();
        String diagnostic = results.getErrorMessage();
        if (diagnostic != null && !diagnostic.isBlank()) {
            warnings.add(warning("decompiler", diagnostic.strip(), null));
        }
        if (results.getCCodeMarkup() == null) return warnings;

        List<ClangNode> tokens = new ArrayList<>();
        results.getCCodeMarkup().flatten(tokens);
        StringBuilder comment = new StringBuilder();
        Address address = null;
        boolean lineComment = false;
        boolean inComment = false;
        for (ClangNode node : tokens) {
            if (node instanceof ClangCommentToken token) {
                String text = token.getText();
                if (!inComment && (text.startsWith("/*") || text.startsWith("//"))) {
                    address = token.getMinAddress();
                    lineComment = text.startsWith("//");
                    inComment = true;
                    comment.append(text.substring(2));
                } else if (inComment) {
                    comment.append(text);
                }
                if (inComment && !lineComment && text.endsWith("*/")) {
                    comment.setLength(comment.length() - 2);
                    addComment(warnings, comment, address);
                    inComment = false;
                }
            } else if (inComment) {
                // The markup represents spaces and wrapped lines as separate
                // syntax/break tokens, even inside a single comment.
                if (node instanceof ClangBreak) {
                    if (lineComment) {
                        addComment(warnings, comment, address);
                        inComment = false;
                    } else comment.append('\n');
                } else if (node instanceof ClangToken token && token.getText().isBlank()) {
                    comment.append(token.getText());
                } else {
                    addComment(warnings, comment, address);
                    inComment = false;
                }
            }
        }
        addComment(warnings, comment, address);
        return warnings;
    }

    private static void addComment(JsonArray warnings, StringBuilder comment, Address address) {
        String message = comment.toString().strip();
        comment.setLength(0);
        // Comment markup does not retain Ghidra's warning/user-comment type.
        // Report provenance as c_comment, never claim an engine diagnostic.
        if (WARNING_PREFIX.matcher(message).find()) {
            warnings.add(warning("c_comment", message, address));
        }
    }

    private static JsonObject warning(String source, String message, Address address) {
        JsonObject warning = new JsonObject();
        warning.addProperty("source", source);
        warning.addProperty("message", message);
        if (address == null) warning.add("address", JsonNull.INSTANCE);
        else warning.addProperty("address", AddressCodec.format(address));
        return warning;
    }
}
