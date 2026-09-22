package ghidracli;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Resolves preserved file bytes without confusing original-file and FileBytes offsets. */
final class MemorySources {
    private MemorySources() {}

    static JsonObject describe(ProgramSession session, Address address) throws Exception {
        Snapshot sources = new Snapshot(session);
        return sources.at(address).description(sources, address);
    }

    static JsonObject fileMappings(ProgramSession session, Long fileOffset, Address sourceAt)
            throws Exception {
        Snapshot sources = new Snapshot(session);
        FileBytes selected = null;
        if (sourceAt != null) {
            Mapping anchor = sources.at(sourceAt);
            if (anchor.fileBytes == null) {
                throw new IllegalArgumentException("source_at has no direct file mapping at "
                    + AddressCodec.format(sourceAt) + ": " + anchor.reason);
            }
            selected = anchor.fileBytes;
        }
        JsonArray rows = new JsonArray();
        JsonArray unsupported = new JsonArray();
        for (Mapping mapping : sources.mappings) {
            session.monitor().checkCancelled();
            if ("unsupported".equals(mapping.state)) {
                JsonObject excluded = new JsonObject();
                excluded.addProperty("address", AddressCodec.format(mapping.start));
                excluded.addProperty("end", AddressCodec.format(mapping.end));
                excluded.addProperty("block_start", AddressCodec.format(mapping.block.getStart()));
                excluded.addProperty("reason", mapping.reason);
                unsupported.add(excluded);
                continue;
            }
            if (mapping.fileBytes == null
                    || (selected != null && !selected.equals(mapping.fileBytes))) continue;
            Address address = mapping.start;
            long length = mapping.length;
            if (fileOffset != null) {
                long first = Math.addExact(mapping.fileBytes.getFileOffset(), mapping.offset);
                if (fileOffset < first || fileOffset - first >= length) continue;
                address = address.addNoWrap(fileOffset - first);
                length = 1;
            }
            rows.add(mapping.range(sources, address, length));
        }
        session.monitor().checkCancelled();
        JsonObject result = new JsonObject();
        result.add("mappings", rows);
        result.addProperty("count", rows.size());
        result.add("unsupported_mappings", unsupported);
        if (fileOffset != null) result.addProperty("file_offset", fileOffset);
        if (sourceAt != null) result.addProperty("source_at", AddressCodec.format(sourceAt));
        return result;
    }

    static JsonArray readOriginal(ProgramSession session, Address address, byte[] bytes) throws Exception {
        JsonArray mappings = new JsonArray();
        if (bytes.length == 0) return mappings;
        // Reject address wrapping before reading any bytes.
        address.addNoWrap(bytes.length - 1);
        Snapshot sources = new Snapshot(session);
        int offset = 0;
        while (offset < bytes.length) {
            session.monitor().checkCancelled();
            Address current = address.addNoWrap(offset);
            Mapping mapping = sources.at(current);
            if (mapping.fileBytes == null) {
                throw new IllegalArgumentException("Original bytes unavailable at "
                    + AddressCodec.format(current) + ": " + mapping.reason);
            }
            int length = (int) Math.min(bytes.length - offset,
                mapping.end.subtract(current) + 1);
            long fileBytesOffset = mapping.offsetAt(current);
            int read = mapping.fileBytes.getOriginalBytes(fileBytesOffset, bytes, offset, length);
            if (read != length) throw new IllegalStateException("Incomplete preserved file read at "
                + AddressCodec.format(current));
            mappings.add(mapping.range(sources, current, length));
            offset += length;
        }
        session.monitor().checkCancelled();
        return mappings;
    }

    /** Request-local: edits, moves and reopened programs must get fresh source anchors. */
    private static final class Snapshot {
        final ProgramSession session;
        final List<Mapping> mappings = new ArrayList<>();
        final Map<MemoryBlock, List<Mapping>> blocks = new HashMap<>();
        // FileBytes equality identifies its database record, not its filename or span.
        final Map<FileBytes, Address> anchors = new HashMap<>();

        Snapshot(ProgramSession session) throws Exception {
            this.session = session;
            session.monitor().checkCancelled();
            for (MemoryBlock block : session.program().getMemory().getBlocks()) {
                session.monitor().checkCancelled();
                List<Mapping> intervals = new ArrayList<>();
                // Native source infos follow the sub-block address order, including joined blocks.
                for (MemoryBlockSourceInfo source : block.getSourceInfos()) {
                    session.monitor().checkCancelled();
                    Mapping mapping = new Mapping(block, source);
                    intervals.add(mapping);
                    mappings.add(mapping);
                    if (mapping.fileBytes != null) {
                        Address previous = anchors.get(mapping.fileBytes);
                        if (previous == null || mapping.start.compareTo(previous) < 0) {
                            anchors.put(mapping.fileBytes, mapping.start);
                        }
                    }
                }
                blocks.put(block, intervals);
            }
            session.monitor().checkCancelled();
        }

        Mapping at(Address address) throws Exception {
            session.monitor().checkCancelled();
            MemoryBlock block = session.program().getMemory().getBlock(address);
            if (block == null) return new Mapping("No memory block at address");
            List<Mapping> intervals = blocks.get(block);
            int low = 0;
            int high = intervals.size() - 1;
            // Original reads across joined blocks must not rescan their entire source list per row.
            while (low <= high) {
                session.monitor().checkCancelled();
                int middle = low + (high - low) / 2;
                Mapping mapping = intervals.get(middle);
                if (address.compareTo(mapping.start) < 0) high = middle - 1;
                else if (address.compareTo(mapping.end) > 0) low = middle + 1;
                else return mapping;
            }
            return new Mapping("No preserved file bytes");
        }
    }

    private static final class Mapping {
        final String state;
        final String reason;
        final MemoryBlock block;
        final Address start;
        final Address end;
        final long length;
        final FileBytes fileBytes;
        final long offset;

        Mapping(String reason) {
            this.state = "unmapped";
            this.reason = reason;
            this.block = null;
            this.start = null;
            this.end = null;
            this.length = 0;
            this.fileBytes = null;
            this.offset = -1;
        }

        Mapping(MemoryBlock block, MemoryBlockSourceInfo source) throws Exception {
            this.block = block;
            this.start = source.getMinAddress();
            this.end = source.getMaxAddress();
            this.length = source.getLength();
            FileBytes file = source.getFileBytes().orElse(null);
            long relative = source.getFileBytesOffset();
            String problem = null;
            // Indirect sources can transform or skip bytes, so never infer a direct correspondence.
            if (source.getMappedRange().isPresent()) {
                problem = "Indirect bit/byte memory mapping";
            } else if (file != null) {
                try {
                    if (relative < 0) problem = "File-byte offset is unavailable";
                    else if (length <= 0 || file.getFileOffset() < 0 || file.getSize() <= 0
                            || length > file.getSize() || relative > file.getSize() - length
                            || !start.addNoWrap(length - 1).equals(end)
                            || source.getFileBytesOffset(end) != Math.addExact(relative, length - 1)) {
                        problem = "Preserved file range is incomplete";
                    } else {
                        Math.addExact(file.getFileOffset(), file.getSize() - 1);
                    }
                } catch (ArithmeticException | ghidra.program.model.address.AddressOverflowException error) {
                    problem = "Preserved file range overflows";
                }
            }
            this.state = problem != null ? "unsupported" : file == null ? "unmapped" : "mapped";
            this.reason = problem != null ? problem : file == null ? "No preserved file bytes" : null;
            this.fileBytes = problem == null ? file : null;
            this.offset = relative;
        }

        long offsetAt(Address address) {
            return Math.addExact(offset, address.subtract(start));
        }

        JsonObject description(Snapshot sources, Address address) {
            JsonObject result = new JsonObject();
            result.addProperty("state", state);
            if (fileBytes == null) {
                result.addProperty("reason", reason);
            } else {
                long relative = offsetAt(address);
                result.addProperty("filename", fileBytes.getFilename());
                result.addProperty("file_offset", Math.addExact(fileBytes.getFileOffset(), relative));
                result.addProperty("file_bytes_offset", relative);
                result.addProperty("source_at", AddressCodec.format(sources.anchors.get(fileBytes)));
                result.addProperty("source_file_offset", fileBytes.getFileOffset());
                result.addProperty("source_size", fileBytes.getSize());
            }
            return result;
        }

        JsonObject range(Snapshot sources, Address address, long size) throws Exception {
            JsonObject result = description(sources, address);
            result.addProperty("address", AddressCodec.format(address));
            result.addProperty("end", AddressCodec.format(address.addNoWrap(size - 1)));
            result.addProperty("size", size);
            result.addProperty("block_start", AddressCodec.format(block.getStart()));
            return result;
        }
    }
}
