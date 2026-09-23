package ghidracli.listing;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.util.DefinedDataIterator;
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

    DefinedStrings definedStrings() {
        return new DefinedStrings();
    }

    final class DefinedStrings {
        private final DataIterator roots = session.program().getListing().getDefinedData(true);
        private DataIterator children;

        Data next() throws CancelledException {
            while (true) {
                session.monitor().checkCancelled();
                if (children != null && children.hasNext()) {
                    return children.next();
                }
                if (!roots.hasNext()) return null;
                // Bound native traversal to one root so skipping unrelated data
                // still observes cancellation between top-level code units.
                Data root = roots.next();
                children = DefinedDataIterator.byDataType(session.program(),
                    new AddressSet(root.getMinAddress(), root.getMaxAddress()),
                    StringDataInstance::isStringDataType);
            }
        }
    }

    JsonArray list(JsonObject args, String pattern) throws CancelledException {
        ListQuery query = new ListQuery(session, args);
        String needle = pattern == null ? "" : pattern.toLowerCase(Locale.ROOT);
        JsonArray rows = new JsonArray();
        DefinedStrings dataIter = definedStrings();
        Data data;
        while (!query.isFull() && (data = dataIter.next()) != null) {
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
        session.monitor().checkCancelled();
        return rows;
    }
}
