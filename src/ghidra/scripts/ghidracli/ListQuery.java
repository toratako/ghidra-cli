package ghidracli;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import ghidra.util.exception.CancelledException;
import java.util.Locale;
import static ghidracli.JsonProtocol.getArgString;

/** Literal contains and paging, applied before constructing result JSON. */
final class ListQuery {
    private final ProgramSession session;
    private final String filter;
    private final long limit;
    private long remainingOffset;
    private long returned;

    ListQuery(ProgramSession session, JsonObject args) {
        this.session = session;
        String value = getArgString(args, "filter");
        filter = value == null ? null : value.toLowerCase(Locale.ROOT);
        limit = pageArgument(args, "limit");
        remainingOffset = pageArgument(args, "offset");
    }

    boolean isFull() throws CancelledException {
        session.monitor().checkCancelled();
        return limit > 0 && returned >= limit;
    }

    /** Call only after all command-specific predicates (such as tags) pass. */
    boolean include(String value) {
        if (filter != null && !value.toLowerCase(Locale.ROOT).contains(filter)) {
            return false;
        }
        if (remainingOffset > 0) {
            remainingOffset--;
            return false;
        }
        return true;
    }

    void record() {
        returned++;
    }

    private static long pageArgument(JsonObject args, String name) {
        if (args == null || !args.has(name) || args.get(name).isJsonNull()) return 0;
        JsonElement value = args.get(name);
        try {
            if (value.isJsonPrimitive() && value.getAsJsonPrimitive().isNumber()) {
                long number = value.getAsBigDecimal().longValueExact();
                if (number >= 0) return number;
            }
        } catch (ArithmeticException | NumberFormatException e) {
            // Reject truncation/overflow instead of turning a page into all rows.
        }
        throw new IllegalArgumentException(name + " must be an integer from 0 to " + Long.MAX_VALUE);
    }
}
