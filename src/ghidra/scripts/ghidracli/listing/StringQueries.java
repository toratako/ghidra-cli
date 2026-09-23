package ghidracli.listing;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.util.exception.CancelledException;
import ghidracli.query.AddressCodec;
import ghidracli.query.ListQuery;
import ghidracli.session.ProgramSession;
import java.util.Locale;

/** Defined string values and their lengths, shared by listing and search. */
public final class StringQueries {
    private final ProgramSession session;

    public StringQueries(ProgramSession session) {
        this.session = session;
    }

    JsonArray list(JsonObject args, String pattern) throws CancelledException {
        ListQuery query = new ListQuery(session, args);
        String needle = pattern == null ? "" : pattern.toLowerCase(Locale.ROOT);
        JsonArray rows = new JsonArray();
        DataIterator dataIter = session.program().getListing().getDefinedData(true);
        while (dataIter.hasNext()) {
            if (query.isFull()) break;
            Data data = dataIter.next();
            if (!data.hasStringValue()) continue;
            String value;
            try {
                Object decoded = data.getValue();
                if (decoded == null) continue;
                value = decoded.toString();
            } catch (Exception e) {
                // Keep unreadable string values out of both listing and search.
                continue;
            }
            // Both predicates must pass before consuming the matching-row offset.
            if (!needle.isEmpty() && !value.toLowerCase(Locale.ROOT).contains(needle)) continue;
            if (!query.include(value)) continue;

            JsonObject row = new JsonObject();
            row.addProperty("address", AddressCodec.format(data.getAddress()));
            row.addProperty("value", value);
            row.addProperty("char_length", value.codePointCount(0, value.length()));
            row.addProperty("byte_length", data.getLength());
            rows.add(row);
            query.record();
        }
        return rows;
    }
}
