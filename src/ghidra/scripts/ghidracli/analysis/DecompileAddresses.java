package ghidracli.analysis;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.exception.CancelledException;
import ghidracli.query.AddressCodec;
import ghidracli.session.ProgramSession;
import java.util.TreeSet;

/** Instruction positions attached to tokens on each rendered C line. */
final class DecompileAddresses {
    private DecompileAddresses() {}

    static JsonArray collect(DecompileResults results, ProgramSession session)
            throws CancelledException {
        JsonArray rows = new JsonArray();
        session.monitor().checkCancelled();
        ClangTokenGroup markup = results.getCCodeMarkup();

        // PrettyPrinter uses the same grouping, including leading blank lines.
        // Keep getC() as the text source so Ghidra still normalizes symbol names.
        for (ClangLine line : DecompilerUtils.toLines(markup)) {
            session.monitor().checkCancelled();
            TreeSet<Address> addresses = new TreeSet<>();
            for (ClangToken token : line.getAllTokens()) {
                session.monitor().checkCancelled();
                PcodeOp op = token.getPcodeOp();
                if (op == null) continue;
                Address address = op.getSeqnum().getTarget();
                if (address != null && !Address.NO_ADDRESS.equals(address)) {
                    addresses.add(address);
                }
            }
            if (addresses.isEmpty()) continue;

            JsonArray values = new JsonArray();
            for (Address address : addresses) {
                session.monitor().checkCancelled();
                values.add(AddressCodec.format(address));
            }
            JsonObject row = new JsonObject();
            row.addProperty("line", line.getLineNumber());
            row.add("addresses", values);
            rows.add(row);
        }
        return rows;
    }
}
