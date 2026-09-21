package ghidracli;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;

/** Resolves preserved file bytes without confusing original-file and FileBytes offsets. */
final class MemorySources {
    private MemorySources() {}

    static JsonObject describe(ProgramSession session, Address address) throws Exception {
        return mappingAt(session, address).description();
    }

    static JsonArray readOriginal(ProgramSession session, Address address, byte[] bytes) throws Exception {
        JsonArray mappings = new JsonArray();
        if (bytes.length == 0) return mappings;
        // Reject address wrapping before reading any bytes.
        address.addNoWrap(bytes.length - 1);
        int offset = 0;
        while (offset < bytes.length) {
            session.monitor().checkCancelled();
            Address current = address.addNoWrap(offset);
            Mapping mapping = mappingAt(session, current);
            if (mapping.fileBytes == null) {
                throw new IllegalArgumentException("Original bytes unavailable at "
                    + AddressCodec.format(current) + ": " + mapping.reason);
            }
            int length = (int) Math.min(bytes.length - offset,
                mapping.source.getMaxAddress().subtract(current) + 1);
            if (mapping.offset > mapping.fileBytes.getSize() - length) {
                throw new IllegalArgumentException("Preserved file range is incomplete at "
                    + AddressCodec.format(current));
            }
            int read = mapping.fileBytes.getOriginalBytes(mapping.offset, bytes, offset, length);
            if (read != length) throw new IllegalStateException("Incomplete preserved file read at "
                + AddressCodec.format(current));
            JsonObject range = mapping.description();
            range.addProperty("address", AddressCodec.format(current));
            range.addProperty("end", AddressCodec.format(current.addNoWrap(length - 1)));
            range.addProperty("size", length);
            mappings.add(range);
            offset += length;
        }
        session.monitor().checkCancelled();
        return mappings;
    }

    private static Mapping mappingAt(ProgramSession session, Address address) throws Exception {
        session.monitor().checkCancelled();
        MemoryBlock block = session.program().getMemory().getBlock(address);
        if (block == null) return new Mapping("unmapped", "No memory block at address");
        for (MemoryBlockSourceInfo source : block.getSourceInfos()) {
            session.monitor().checkCancelled();
            if (!source.contains(address)) continue;
            // Bit/byte mapped sources can transform or skip bytes. Ghidra's convenience
            // AddressSourceInfo follows them as if they were 1:1 and cannot prove this mapping.
            if (source.getMappedRange().isPresent()) {
                return new Mapping("unsupported", "Indirect bit/byte memory mapping");
            }
            FileBytes fileBytes = source.getFileBytes().orElse(null);
            if (fileBytes == null) return new Mapping("unmapped", "No preserved file bytes");
            long offset = source.getFileBytesOffset(address);
            if (offset < 0) return new Mapping("unsupported", "File-byte offset is unavailable");
            return new Mapping(source, fileBytes, offset);
        }
        return new Mapping("unmapped", "No preserved file bytes");
    }

    private static final class Mapping {
        final String state;
        final String reason;
        final MemoryBlockSourceInfo source;
        final FileBytes fileBytes;
        final long offset;

        Mapping(String state, String reason) {
            this.state = state;
            this.reason = reason;
            this.source = null;
            this.fileBytes = null;
            this.offset = -1;
        }

        Mapping(MemoryBlockSourceInfo source, FileBytes fileBytes, long offset) {
            this.state = "mapped";
            this.reason = null;
            this.source = source;
            this.fileBytes = fileBytes;
            this.offset = offset;
        }

        JsonObject description() {
            JsonObject result = new JsonObject();
            result.addProperty("state", state);
            if (fileBytes == null) {
                result.addProperty("reason", reason);
            } else {
                result.addProperty("filename", fileBytes.getFilename());
                result.addProperty("file_offset", Math.addExact(fileBytes.getFileOffset(), offset));
                result.addProperty("file_bytes_offset", offset);
            }
            return result;
        }
    }
}
