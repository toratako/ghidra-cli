package ghidracli.listing;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.util.DefinedDataIterator;
import ghidra.util.exception.CancelledException;
import ghidracli.memory.MemoryReads;
import ghidracli.query.AddressCodec;
import ghidracli.query.ListQuery;
import ghidracli.session.ProgramSession;
import java.util.Locale;
import java.util.concurrent.CancellationException;

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
      try {
        while (true) {
          session.monitor().checkCancelled();
          if (children != null && children.hasNext()) {
            return children.next();
          }
          if (!roots.hasNext()) return null;
          Data root = roots.next();
          children =
              DefinedDataIterator.byDataType(
                  session.program(),
                  new AddressSet(root.getMinAddress(), root.getMaxAddress()),
                  type -> {
                    // Native traversal can visit every padding byte of a sparse
                    // structure before returning from hasNext().
                    if (session.monitor().isCancelled()) throw new CancellationException();
                    return StringDataInstance.isStringDataType(type);
                  });
        }
      } catch (CancellationException cancelled) {
        throw new CancelledException();
      }
    }
  }

  String value(Data data) throws Exception {
    session.monitor().checkCancelled();
    if (!data.hasStringValue()) return null;
    // Component reads through Data populate the entire root object's byte
    // cache, even for a short string in a huge aggregate.
    var reads = new MemoryReads(session);
    var buffer = reads.buffer(data.getAddress());
    try {
      var string =
          StringDataInstance.getStringDataInstance(
              data.getBaseDataType(), buffer, data, data.getLength());
      int length = string.getStringLength();
      // A char array can terminate before its uninitialized trailing storage.
      // Check only the bytes consumed by the native string interpretation.
      if (length < 0) return null;
      byte[] bytes = new byte[Math.min(length, 16 * 1024)];
      for (int offset = 0; offset < length; ) {
        int requested = Math.min(bytes.length, length - offset);
        if (reads.read(data.getAddress().addNoWrap(offset), bytes, 0, requested) != requested)
          return null;
        offset += requested;
      }
      // Array.getValue additionally consults the incomplete native
      // initialized set. Decode the already validated native instance.
      String value = string.getStringValue();
      session.monitor().checkCancelled();
      return value;
    } catch (AddressOverflowException | ghidra.program.model.mem.MemoryAccessException unreadable) {
      // A patched Pascal length prefix can extend beyond the address
      // space even though the stored data unit still fits in memory.
      return null;
    } catch (CancellationException cancelled) {
      throw new CancelledException();
    }
  }

  JsonArray list(JsonObject args, String pattern) throws CancelledException {
    ListQuery query = new ListQuery(session, args);
    String needle = pattern == null ? "" : pattern.toLowerCase(Locale.ROOT);
    JsonArray rows = new JsonArray();
    DefinedStrings dataIter = definedStrings();
    Data data;
    while (!query.isFull() && (data = dataIter.next()) != null) {
      String value;
      try {
        value = value(data);
        if (value == null) continue;
      } catch (CancelledException cancelled) {
        throw cancelled;
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
