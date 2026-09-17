package ghidracli;

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

    static long pageArgument(JsonObject args, String name) {
        return JsonProtocol.getNonnegativeLongArg(args, name);
    }
}
