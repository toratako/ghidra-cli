package ghidracli.memory;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import ghidra.util.GhidraDataConverter;
import ghidra.util.exception.CancelledException;
import ghidracli.query.AddressCodec;
import ghidracli.session.ProgramSession;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CancellationException;

/** Request-local reads that resolve mapped bytes without native recursion. */
public final class MemoryReads {
    private static final int MAX_CACHED_BYTES = 64 * 1024;
    private final ProgramSession session;
    private final Memory memory;
    private final Map<Address, Byte> resolved = new LinkedHashMap<>(16, 0.75f, true) {
        protected boolean removeEldestEntry(Map.Entry<Address, Byte> entry) {
            return size() > MAX_CACHED_BYTES;
        }
    };

    public MemoryReads(ProgramSession session) {
        this.session = session;
        this.memory = session.program().getMemory();
    }

    /** Complete native initialized intervals through mappings, regardless of block order. */
    public AddressSetView initializedAddresses() throws CancelledException {
        AddressSet initialized = new AddressSet(memory.getAllInitializedAddressSet());
        boolean changed;
        do {
            changed = false;
            for (var block : memory.getBlocks()) {
                session.monitor().checkCancelled();
                if (!block.isMapped()) continue;
                for (var source : block.getSourceInfos()) {
                    var mapped = source.getMappedRange();
                    if (mapped.isEmpty()) continue;
                    Address origin = mapped.get().getMinAddress();
                    var scheme = source.getByteMappingScheme();
                    for (var range : initialized.intersectRange(origin, mapped.get().getMaxAddress())) {
                        session.monitor().checkCancelled();
                        long first = range.getMinAddress().subtract(origin);
                        long last = range.getMaxAddress().subtract(origin);
                        if (scheme.isPresent()) {
                            int mappedBytes = scheme.get().getMappedByteCount();
                            int sourceBytes = scheme.get().getMappedSourceByteCount();
                            first = first / sourceBytes * mappedBytes + Math.min(first % sourceBytes, mappedBytes);
                            last = last / sourceBytes * mappedBytes + Math.min(last % sourceBytes, mappedBytes - 1);
                        } else {
                            first *= 8;
                            last = last * 8 + 7;
                        }
                        last = Math.min(last, source.getLength() - 1);
                        if (first > last) continue;
                        // An overlapping 1:1 translation repeats the same rule
                        // within this source interval. Once a readable interval
                        // spans every residue of the shift, extend through all
                        // hops at once instead of one byte per fixed-point pass.
                        if (scheme.isPresent() && scheme.get().getMappedByteCount() == 1
                                && scheme.get().getMappedSourceByteCount() == 1
                                && origin.getAddressSpace().equals(source.getMinAddress().getAddressSpace())) {
                            long shift = origin.subtract(source.getMinAddress());
                            if (shift > 0 && shift < source.getLength() && last - first + 1 >= shift)
                                first = 0;
                            else if (shift < 0 && shift > -source.getLength() && last - first + 1 >= -shift)
                                last = source.getLength() - 1;
                        }
                        Address start = source.getMinAddress().add(first);
                        Address end = source.getMinAddress().add(last);
                        if (!initialized.contains(start, end)) {
                            initialized.add(start, end);
                            changed = true;
                        }
                    }
                }
            }
        } while (changed);
        return initialized;
    }

    /** Readable initialized ranges belonging to the loaded program image. */
    public AddressSetView loadedInitializedAddresses() throws CancelledException {
        AddressSet initialized = new AddressSet(initializedAddresses());
        for (var block : memory.getBlocks()) {
            session.monitor().checkCancelled();
            if (!block.isLoaded()) initialized.delete(block.getStart(), block.getEnd());
        }
        return initialized;
    }

    public byte readByte(Address address) throws MemoryAccessException, CancelledException {
        Address current = address;
        List<Address> path = new ArrayList<>();
        List<Integer> bits = new ArrayList<>();
        Address checkpoint = address;
        long checkpointDistance = 0;
        long checkpointPeriod = 1;
        int tailBit = -1;
        byte value;
        while (true) {
            session.monitor().checkCancelled();
            Byte cached = resolved.get(current);
            if (cached != null) { value = cached; break; }
            var block = memory.getBlock(current);
            if (block == null || !block.isMapped()) {
                value = memory.getByte(current);
                break;
            }
            MemoryBlockSourceInfo source = null;
            for (var candidate : block.getSourceInfos()) {
                if (candidate.contains(current)) { source = candidate; break; }
            }
            if (source == null || source.getMappedRange().isEmpty())
                throw new MemoryAccessException("Unreadable memory mapping at " + AddressCodec.format(current));
            long offset = current.subtract(source.getMinAddress());
            Address mapped = source.getMappedRange().get().getMinAddress();
            var scheme = source.getByteMappingScheme();
            Address previous = current;
            int bit;
            try {
                if (scheme.isPresent()) {
                    bit = -1;
                    current = scheme.get().getMappedSourceAddress(mapped, offset);
                } else {
                    bit = (int) (offset % 8);
                    current = mapped.addNoWrap(offset / 8);
                }
            } catch (AddressOverflowException overflow) {
                throw new MemoryAccessException("Unreadable mapped source at " + AddressCodec.format(current));
            }
            if (path.size() < MAX_CACHED_BYTES) {
                path.add(previous);
                bits.add(bit);
            } else if (bit >= 0) {
                // Compose the uncached suffix: selecting a nonzero bit from
                // another bit mapping always produces zero.
                tailBit = tailBit == -1 || tailBit == 0 ? bit : -2;
            }
            // Brent cycle detection retains one address regardless of depth.
            // Self-shifted blocks can encode millions of hops in a single block.
            checkpointDistance++;
            if (current.equals(checkpoint))
                throw new MemoryAccessException("Cyclic unreadable memory mapping at " + AddressCodec.format(current));
            if (checkpointDistance == checkpointPeriod) {
                checkpoint = current;
                checkpointDistance = 0;
                checkpointPeriod *= 2;
            }
        }
        if (tailBit == -2) value = 0;
        else if (tailBit >= 0) value = (byte) ((value >>> tailBit) & 1);
        for (int i = bits.size() - 1; i >= 0; i--) {
            session.monitor().checkCancelled();
            if (bits.get(i) >= 0) value = (byte) ((value >>> bits.get(i)) & 1);
            resolved.put(path.get(i), value);
        }
        return value;
    }

    /** Return the readable prefix; an unreadable first byte fails the read. */
    public int read(Address address, byte[] bytes, int offset, int length)
            throws MemoryAccessException, CancelledException {
        Objects.checkFromIndexSize(offset, length, bytes.length);
        int read = 0;
        while (read < length) {
            session.monitor().checkCancelled();
            try {
                Address current = address.addNoWrap(read);
                var block = memory.getBlock(current);
                if (block == null || block.isMapped()) {
                    bytes[offset + read] = readByte(current);
                    read++;
                } else {
                    int requested = (int) Math.min(length - read,
                        block.getSize() - current.subtract(block.getStart()));
                    int consumed = memory.getBytes(current, bytes, offset + read, requested);
                    read += consumed;
                    if (consumed < requested) break;
                }
            } catch (MemoryAccessException | AddressOverflowException boundary) {
                if (read == 0) throw new MemoryAccessException(boundary.getMessage());
                break;
            }
        }
        return read;
    }

    /** A native datatype buffer without eager root/cache reads or mapping recursion. */
    public MemBuffer buffer(Address address) {
        return new MemBuffer() {
            private final GhidraDataConverter converter = GhidraDataConverter.getInstance(memory.isBigEndian());

            public Address getAddress() { return address; }
            public Memory getMemory() { return memory; }
            public boolean isBigEndian() { return memory.isBigEndian(); }
            public byte getByte(int offset) throws MemoryAccessException {
                try { return readByte(address.addNoWrap(offset)); }
                catch (AddressOverflowException overflow) { throw new MemoryAccessException(overflow.getMessage()); }
                catch (CancelledException cancelled) { throw new CancellationException(); }
            }
            public int getBytes(byte[] bytes, int offset) {
                try { return read(address.addNoWrap(offset), bytes, 0, bytes.length); }
                catch (MemoryAccessException | AddressOverflowException unreadable) { return 0; }
                catch (CancelledException cancelled) { throw new CancellationException(); }
            }
            public short getShort(int offset) throws MemoryAccessException { return converter.getShort(this, offset); }
            public int getInt(int offset) throws MemoryAccessException { return converter.getInt(this, offset); }
            public long getLong(int offset) throws MemoryAccessException { return converter.getLong(this, offset); }
            public BigInteger getBigInteger(int offset, int size, boolean signed) throws MemoryAccessException {
                return converter.getBigInteger(this, offset, size, signed);
            }
        };
    }
}
