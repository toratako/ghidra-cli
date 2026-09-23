package ghidracli.memory;

import ghidra.program.database.data.PointerTypedefInspector;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.OverlayAddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.WrappedMemBuffer;
import ghidra.program.model.symbol.OffsetReference;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidracli.query.AddressCodec;
import ghidracli.session.ProgramSession;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/** Preflight a byte edit without rebuilding data or borrowing instruction metadata. */
final class MemoryPatch {
    private static final Set<Class<?>> STRING_TYPES = Set.of(
        StringDataType.class, StringUTF8DataType.class, UnicodeDataType.class,
        Unicode32DataType.class, TerminatedStringDataType.class,
        TerminatedUnicodeDataType.class, TerminatedUnicode32DataType.class,
        PascalStringDataType.class, PascalString255DataType.class, PascalUnicodeDataType.class);

    private final ProgramSession session;
    private final Address address;
    private final byte[] bytes;
    private final AddressSet changed = new AddressSet();
    private final AddressSet instructions = new AddressSet();
    private final Set<Address> inspected = new HashSet<>();
    private final List<PointerEdit> pointers = new ArrayList<>();

    private MemoryPatch(ProgramSession session, Address address, byte[] bytes) {
        this.session = session;
        this.address = address;
        this.bytes = bytes;
    }

    static void write(ProgramSession session, Address address, byte[] bytes) throws Exception {
        MemoryPatch patch = new MemoryPatch(session, address, bytes);
        patch.prepare();
        patch.apply();
    }

    private void prepare() throws Exception {
        var memory = session.program().getMemory();
        Address end = address.addNoWrap(bytes.length - 1);
        if (!memory.getAllInitializedAddressSet().contains(address, end)) {
            throw new IllegalArgumentException("Patch range must be fully mapped and initialized");
        }
        byte[] before = new byte[bytes.length];
        if (memory.getBytes(address, before) != before.length) {
            throw new MemoryAccessException("Could not read the complete patch range");
        }
        for (int i = 0; i < bytes.length;) {
            session.monitor().checkCancelled();
            if (before[i] == bytes[i]) { i++; continue; }
            int start = i++;
            while (i < bytes.length && before[i] != bytes[i]) i++;
            changed.add(address.add(start), address.add(i - 1));
        }
        if (changed.isEmpty()) return;

        // Both writes through a mapping and writes to its source affect other
        // addresses. Until those views can be validated together, reject them.
        for (var block : memory.getBlocks()) {
            session.monitor().checkCancelled();
            if (!block.isMapped()) continue;
            boolean affected = changed.intersects(block.getStart(), block.getEnd());
            for (var source : block.getSourceInfos()) {
                var mapped = source.getMappedRange();
                if (mapped.isPresent()) {
                    AddressRange range = mapped.get();
                    affected |= changed.intersects(range.getMinAddress(), range.getMaxAddress());
                }
            }
            if (affected) {
                throw new IllegalArgumentException("Patch changes shared mapped memory (block "
                    + block.getName() + "); edits through its aliases cannot be preserved safely");
            }
        }

        var listing = session.program().getListing();
        for (AddressRange range : changed) {
            // Set-based listing iterators may omit units starting before a range.
            inspect(listing.getDefinedDataContaining(range.getMinAddress()));
            include(listing.getInstructionContaining(range.getMinAddress()));
        }
        for (Data data : listing.getDefinedData(changed, true)) inspect(data);
        for (Instruction instruction : listing.getInstructions(changed, true)) include(instruction);
    }

    private void include(Instruction instruction) throws Exception {
        session.monitor().checkCancelled();
        if (instruction != null) {
            instructions.add(instruction.getMinAddress(), instruction.getMaxAddress());
        }
    }

    private void inspect(Data data) throws Exception {
        if (data != null && inspected.add(data.getMinAddress())) inspect(data, true);
    }

    private void inspect(Data data, boolean followPointers) throws Exception {
        session.monitor().checkCancelled();
        if (data.getLength() <= 0 || !changed.intersects(data.getMinAddress(), data.getMaxAddress())) return;
        DataType type = data.getBaseDataType();
        if (type instanceof Dynamic) {
            if (!STRING_TYPES.contains(type.getClass())) {
                throw cannotPreserve(data, "dynamic data layout cannot be verified");
            }
            AbstractStringDataType string = (AbstractStringDataType) type;
            if (!string.getStringLayout().isFixedLen()) {
                int required = string.getStringDataInstance(new PatchedBuffer(data), data,
                    data.getLength()).getStringLength();
                if (required != data.getLength()) {
                    throw cannotPreserve(data, "string occupied length would change or its terminator is missing");
                }
            }
        } else if (Address.class.equals(data.getDataType().getValueClass(data))) {
            // Ghidra also generates references for address-valued built-ins
            // such as ShiftedAddress, which do not implement Pointer.
            if (followPointers) inspectPointer(data);
        } else if (type instanceof Array) {
            Array array = (Array) type;
            // Ghidra displays zero-length arrays as one byte, without elements.
            if (array.getNumElements() == 0) return;
            int elementLength = array.getElementLength();
            int last = -1;
            for (AddressRange range : changed.intersectRange(data.getMinAddress(), data.getMaxAddress())) {
                int first = (int) (range.getMinAddress().subtract(data.getMinAddress()) / elementLength);
                int end = (int) (range.getMaxAddress().subtract(data.getMinAddress()) / elementLength);
                for (int i = Math.max(first, last + 1); i <= end; i++) {
                    inspect(data.getComponent(i), followPointers);
                }
                last = end;
            }
        } else if (type instanceof Composite) {
            // Validate all overlapping union interpretations, but never choose
            // an active member for automatic pointer reference generation.
            for (var component : ((Composite) type).getDefinedComponents()) {
                inspect(data.getComponent(component.getOrdinal()), followPointers && !(type instanceof Union));
            }
        }
    }

    private IllegalArgumentException cannotPreserve(Data data, String reason) {
        return new IllegalArgumentException("Cannot preserve " + data.getDataType().getPathName()
            + " at " + AddressCodec.format(data.getMinAddress()) + ": " + reason
            + "; use clear, memory write, then apply the intended data type");
    }

    private void inspectPointer(Data data) {
        long offset = data.getDataType() instanceof TypeDef
            ? PointerTypedefInspector.getPointerComponentOffset((TypeDef) data.getDataType()) : 0;
        AutoReference before = AutoReference.from(data.getValue(), offset);
        Object value = data.getDataType().getValue(new PatchedBuffer(data), data, data.getLength());
        AutoReference after = AutoReference.from(value, offset);
        if (Objects.equals(before, after)) return;

        Reference owned = null;
        boolean protectedOperand = false;
        for (Reference ref : session.program().getReferenceManager().getReferencesFrom(data.getMinAddress())) {
            if (ref.getOperandIndex() != 0) continue;
            if (before != null && before.matches(ref)) owned = ref;
            else protectedOperand = true;
        }
        pointers.add(new PointerEdit(data.getMinAddress(), owned, protectedOperand ? null : after));
    }

    private void apply() throws Exception {
        var listing = session.program().getListing();
        for (AddressRange range : instructions) {
            session.monitor().checkCancelled();
            // Ghidra expands this to complete instructions and delay slots.
            listing.clearCodeUnits(range.getMinAddress(), range.getMaxAddress(), false, session.monitor());
        }
        for (AddressRange range : changed) {
            session.monitor().checkCancelled();
            int offset = (int) range.getMinAddress().subtract(address);
            session.program().getMemory().setBytes(range.getMinAddress(), bytes, offset, (int) range.getLength());
        }
        ReferenceManager refs = session.program().getReferenceManager();
        for (PointerEdit edit : pointers) {
            session.monitor().checkCancelled();
            if (edit.before != null) refs.delete(edit.before);
            if (edit.after != null) edit.after.add(refs, edit.address);
        }
    }

    private record PointerEdit(Address address, Reference before, AutoReference after) {}

    private record AutoReference(Address target, long offset) {
        static AutoReference from(Object value, long offset) {
            if (!(value instanceof Address)) return null;
            Address target = (Address) value;
            // Ghidra treats zero and the address-space maximum as uninitialized
            // pointer values after interpreting the applied type's settings.
            if (!target.isLoadedMemoryAddress() || target.getOffset() == 0
                    || target.equals(target.getAddressSpace().getMaxAddress())) return null;
            return new AutoReference(target, offset);
        }

        private static Address translated(Address address) {
            return address.getAddressSpace() instanceof OverlayAddressSpace
                ? ((OverlayAddressSpace) address.getAddressSpace()).translateAddress(address) : address;
        }

        boolean matches(Reference ref) {
            if (ref.getSource() != SourceType.DEFAULT || ref.getReferenceType() != RefType.DATA
                    || !ref.isMemoryReference() || ref.isShiftedReference()
                    || !ref.getToAddress().equals(translated(target))) return false;
            if (offset == 0) return !ref.isOffsetReference();
            return ref instanceof OffsetReference && ((OffsetReference) ref).getOffset() == offset
                && ((OffsetReference) ref).getBaseAddress().equals(translated(target.subtractWrap(offset)));
        }

        void add(ReferenceManager refs, Address from) {
            Reference added = offset == 0
                ? refs.addMemoryReference(from, target, RefType.DATA, SourceType.DEFAULT, 0)
                : refs.addOffsetMemReference(from, target.subtractWrap(offset), true, offset,
                    RefType.DATA, SourceType.DEFAULT, 0);
            if (added == null) throw new IllegalStateException("Ghidra failed to create a pointer reference at "
                + AddressCodec.format(from));
        }
    }

    /** Bounded, read-only view of the existing data with the requested bytes overlaid. */
    private final class PatchedBuffer extends WrappedMemBuffer {
        private final int length;
        private final long patchOffset;

        PatchedBuffer(Data data) {
            super(data, 0);
            length = data.getLength();
            patchOffset = address.subtract(data.getMinAddress());
        }

        @Override
        public byte getByte(int offset) throws MemoryAccessException {
            if (offset < 0 || offset >= length) throw new MemoryAccessException("Outside data definition");
            long index = offset - patchOffset;
            return index >= 0 && index < bytes.length ? bytes[(int) index] : super.getByte(offset);
        }

        @Override
        public int getBytes(byte[] buffer, int offset) {
            int read = 0;
            try {
                while (read < buffer.length && (long) offset + read < length) {
                    buffer[read] = getByte(offset + read);
                    read++;
                }
            } catch (MemoryAccessException e) {
                // MemBuffer reports short reads at the definition boundary.
            }
            return read;
        }
    }
}
