package ghidracli.query;

import com.google.gson.JsonObject;
import ghidra.util.exception.CancelledException;
import ghidracli.protocol.JsonProtocol;
import ghidracli.session.ProgramSession;
import java.util.Locale;

import static ghidracli.protocol.JsonProtocol.getArgString;

/** Literal contains and paging, applied before constructing result JSON. */
public final class ListQuery {
    private final ProgramSession session;
    private final String filter;
    private final long limit;
    private long remainingOffset;
    private long returned;

    public ListQuery(ProgramSession session, JsonObject args) {
        this.session = session;
        String value = getArgString(args, "filter");
        filter = value == null ? null : value.toLowerCase(Locale.ROOT);
        limit = pageArgument(args, "limit");
        remainingOffset = pageArgument(args, "offset");
    }

    public boolean isFull() throws CancelledException {
        session.monitor().checkCancelled();
        return limit > 0 && returned >= limit;
    }

    /** Call only after all command-specific predicates (such as tags) pass. */
    public boolean include(String value) {
        if (filter != null && !value.toLowerCase(Locale.ROOT).contains(filter)) {
            return false;
        }
        if (remainingOffset > 0) {
            remainingOffset--;
            return false;
        }
        return true;
    }

    public void record() {
        returned++;
    }

    public static long pageArgument(JsonObject args, String name) {
        return JsonProtocol.getNonnegativeLongArg(args, name);
    }
}
