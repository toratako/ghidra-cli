package ghidracli.analysis;

import com.google.gson.JsonObject;
import ghidracli.query.AddressResolver;
import ghidracli.session.ProgramSession;

import static ghidracli.protocol.JsonProtocol.errorResult;

/** Public command adapter for the shared read-only ABI table reader. */
public final class VtableCommands {
    private final ProgramSession session;
    private final VtableReader reader;

    public VtableCommands(ProgramSession session, AddressResolver addresses) {
        this.session = session;
        reader = new VtableReader(session, addresses);
    }

    public JsonObject handleRead(JsonObject args) throws Exception {
        if (session.program() == null) return errorResult("No program loaded");
        return reader.read(args);
    }
}
