package ghidracli.memory;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidracli.query.AddressCodec;
import ghidracli.query.IntegerLiteral;
import ghidracli.session.ProgramSession;

import static ghidracli.protocol.JsonProtocol.errorResult;

/** Lists direct preserved-file intervals or every mapping of one original-file byte. */
public final class FileMappingCommands {
    private final ProgramSession session;

    public FileMappingCommands(ProgramSession session) {
        this.session = session;
    }

    public JsonObject handleFileMappings(JsonObject args) throws Exception {
        if (session.program() == null) return errorResult("No program loaded");
        Long fileOffset = null;
        if (args.has("file_offset")) {
            String text = requireString(args, "file_offset");
            try {
                fileOffset = IntegerLiteral.parse(text).longValueExact();
            } catch (NumberFormatException | ArithmeticException error) {
                throw invalidOffset();
            }
            if (fileOffset < 0) throw invalidOffset();
        }
        Address sourceAt = null;
        if (args.has("source_at")) {
            String text = requireString(args, "source_at");
            sourceAt = AddressCodec.parse(session.program().getAddressFactory(), text);
            if (sourceAt == null) throw new IllegalArgumentException("source_at must be an explicit address: " + text);
        }
        return MemorySources.fileMappings(session, fileOffset, sourceAt);
    }

    private static String requireString(JsonObject args, String key) {
        JsonElement value = args.get(key);
        if (value == null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString()) {
            throw new IllegalArgumentException(key + " must be a string");
        }
        return value.getAsString();
    }

    private static IllegalArgumentException invalidOffset() {
        return new IllegalArgumentException("file_offset must be a nonnegative decimal or 0x-prefixed integer from 0 to " + Long.MAX_VALUE);
    }
}
