package ghidracli.analysis;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.exception.CancelledException;
import ghidracli.query.AddressCodec;
import ghidracli.session.ProgramSession;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Bounded, request-local def/use evidence for absolute virtual-table slots. */
final class VirtualCallTrace {
    record Findings(JsonArray calls, JsonArray unresolved) {}

    private static final int MAX_STEPS = 4096;
    private static final int MAX_DEPTH = 96;
    private static final int MAX_LOAD_SITES = 16;

    // Raw p-code is used only within its original instruction. Its varnodes are
    // not SSA values: before records which definition can actually reach a use.
    private record Value(Varnode node, PcodeOp[] raw, int before) {}
    private record Definition(PcodeOp operation, int index) {}
    private record Candidate(long offset, String evidence, DataType type, Set<Address> loadSites) {}

    private final ProgramSession session;
    private final Function function;
    private final Address addressPoint;
    private final Set<Long> slotOffsets;
    private final DataTypeManager manager;
    private final DataType tableType;
    private final JsonArray calls = new JsonArray();
    private final JsonArray unresolved = new JsonArray();

    private VirtualCallTrace(ProgramSession session, Function function, Address addressPoint,
            Set<Long> slotOffsets) throws CancelledException {
        this.session = session;
        this.function = function;
        this.addressPoint = addressPoint;
        this.slotOffsets = slotOffsets;
        manager = session.program().getDataTypeManager();
        Data applied = session.program().getListing().getDataAt(addressPoint);
        DataType type = applied == null || !applied.isDefined() ? null : base(applied.getDataType());
        tableType = type instanceof Structure
            || type instanceof Array array && base(array.getDataType()) instanceof Pointer ? type : null;
    }

    static Findings find(ProgramSession session, Function function, DecompileResults results,
            Address addressPoint, Set<Long> slotOffsets) throws Exception {
        VirtualCallTrace scan = new VirtualCallTrace(session, function, addressPoint, slotOffsets);
        Map<Address, List<PcodeOp>> highCalls = new LinkedHashMap<>();
        var iterator = results.getHighFunction().getPcodeOps();
        while (iterator.hasNext()) {
            session.monitor().checkCancelled();
            PcodeOp op = iterator.next();
            if (op.getOpcode() == PcodeOp.CALLIND || op.getOpcode() == PcodeOp.CALL) {
                highCalls.computeIfAbsent(op.getSeqnum().getTarget(), ignored -> new ArrayList<>())
                    .add(op);
            }
        }
        // Listing identity prevents a decompiler CALL from being mistaken for a
        // machine indirect call, and retains indirect calls optimized out of SSA.
        var instructions = session.program().getListing().getInstructions(function.getBody(), true);
        while (instructions.hasNext()) {
            session.monitor().checkCancelled();
            Instruction instruction = instructions.next();
            PcodeOp[] raw = instruction.getPcode(false);
            List<Integer> indirect = new ArrayList<>();
            for (int i = 0; i < raw.length; i++) {
                session.monitor().checkCancelled();
                if (raw[i].getOpcode() == PcodeOp.CALLIND) indirect.add(i);
            }
            if (indirect.isEmpty()) continue;
            Trace trace = scan.new Trace(instruction.getAddress());
            boolean usedHigh = false;
            for (PcodeOp op : highCalls.getOrDefault(instruction.getAddress(), List.of())) {
                if (op.getOpcode() != PcodeOp.CALLIND) continue;
                usedHigh = true;
                trace.target(new Value(op.getInput(0), null, -1), 0);
            }
            if (!usedHigh) {
                for (int index : indirect) {
                    trace.target(new Value(raw[index].getInput(0), raw, index), 0);
                }
                if (trace.matches.isEmpty() && !trace.reasons.isEmpty()) {
                    trace.reasons.add("indirect_call_not_preserved_in_high_pcode");
                }
            }
            trace.finish();
        }
        session.monitor().checkCancelled();
        return new Findings(scan.calls, scan.unresolved);
    }

    private final class Trace {
        private final Address site;
        private final Map<Long, Candidate> matches = new LinkedHashMap<>();
        private final Set<String> reasons = new LinkedHashSet<>();
        private final Set<Varnode> path = Collections.newSetFromMap(new IdentityHashMap<>());
        private int steps;
        private boolean merged;

        Trace(Address site) { this.site = site; }

        private boolean enter(Value value, int depth) throws CancelledException {
            session.monitor().checkCancelled();
            if (++steps > MAX_STEPS || depth > MAX_DEPTH) {
                reasons.add("trace_limit");
                return false;
            }
            if (value.node() == null) {
                reasons.add("missing_value");
                return false;
            }
            if (!path.add(value.node())) {
                reasons.add("cyclic_value_flow");
                return false;
            }
            return true;
        }

        private void target(Value value, int depth) throws CancelledException {
            if (!enter(value, depth)) return;
            try {
                Definition definition = definition(value);
                if (definition == null) {
                    // High p-code represents some global memory reads as RAM
                    // varnodes, without a separate LOAD operation.
                    if (value.raw() == null && value.node().isAddress()
                            && value.node().getAddress().isMemoryAddress()) {
                        if (value.node().getSize() == session.program().getDefaultPointerSize()) {
                            concrete(value.node().getAddress(), 0, null);
                        } else {
                            reasons.add("unsupported_pointer_width");
                        }
                    } else {
                        reasons.add("indirect_target_not_traced_to_slot");
                    }
                    return;
                }
                PcodeOp op = definition.operation();
                switch (op.getOpcode()) {
                    case PcodeOp.COPY, PcodeOp.CAST -> {
                        if (sameWidth(op)) target(input(value, definition, 0), depth + 1);
                        else reasons.add("pointer_width_changed");
                    }
                    case PcodeOp.MULTIEQUAL -> {
                        merged |= op.getNumInputs() > 1;
                        for (int i = 0; i < op.getNumInputs() && steps <= MAX_STEPS; i++) {
                            target(input(value, definition, i), depth + 1);
                        }
                    }
                    case PcodeOp.LOAD -> {
                        if (op.getOutput() == null || op.getOutput().getSize()
                                != session.program().getDefaultPointerSize()) {
                            reasons.add("unsupported_pointer_width");
                            return;
                        }
                        AddressSpace space = session.program().getAddressFactory()
                            .getAddressSpace((int) op.getInput(0).getOffset());
                        if (space == null || !space.isMemorySpace()) {
                            reasons.add("unsupported_load_space");
                            return;
                        }
                        if (space.getAddressableUnitSize() != 1) {
                            reasons.add("unsupported_addressable_unit_size");
                            return;
                        }
                        pointer(input(value, definition, 1), space, 0, false,
                            op.getSeqnum().getTarget(), depth + 1);
                    }
                    // INDIRECT records a side effect, not an unchanged value.
                    case PcodeOp.INDIRECT -> reasons.add("indirect_side_effect");
                    default -> reasons.add("unsupported_target_operation_" + op.getMnemonic().toLowerCase(java.util.Locale.ROOT));
                }
            } finally {
                path.remove(value.node());
            }
        }

        private void pointer(Value value, AddressSpace space, long offset, boolean typed,
                Address loadSite, int depth)
                throws CancelledException {
            // LOAD's space identifies the memory being read even when its pointer
            // base is unknown. Matching offsets in another overlay are unrelated.
            if (!space.equals(addressPoint.getAddressSpace())) return;
            if (!enter(value, depth)) return;
            try {
                typed |= tablePointer(value.node());
                if (value.node().isConstant()) {
                    concrete(space.getAddress(value.node().getOffset()), offset, loadSite);
                    return;
                }
                Definition definition = definition(value);
                if (definition == null) {
                    candidate(offset, typed, loadSite);
                    return;
                }
                PcodeOp op = definition.operation();
                switch (op.getOpcode()) {
                    case PcodeOp.COPY, PcodeOp.CAST -> {
                        if (sameWidth(op)) pointer(input(value, definition, 0), space, offset, typed, loadSite, depth + 1);
                        else reasons.add("pointer_width_changed");
                    }
                    case PcodeOp.MULTIEQUAL -> {
                        merged |= op.getNumInputs() > 1;
                        for (int i = 0; i < op.getNumInputs() && steps <= MAX_STEPS; i++) {
                            pointer(input(value, definition, i), space, offset, typed, loadSite, depth + 1);
                        }
                    }
                    case PcodeOp.PTRSUB, PcodeOp.INT_ADD, PcodeOp.INT_SUB -> {
                        Value base = input(value, definition, 0);
                        Long addition = constant(input(value, definition, 1), depth + 1,
                            Collections.newSetFromMap(new IdentityHashMap<>()));
                        if (addition == null && op.getOpcode() == PcodeOp.INT_ADD) {
                            addition = constant(base, depth + 1,
                                Collections.newSetFromMap(new IdentityHashMap<>()));
                            base = input(value, definition, 1);
                        }
                        if (addition == null) {
                            reasons.add("dynamic_slot_offset");
                            return;
                        }
                        try {
                            if (op.getOpcode() == PcodeOp.INT_SUB) addition = Math.negateExact(addition);
                            long nextOffset = Math.addExact(offset, addition);
                            if (offsetFits(op, nextOffset)) {
                                pointer(base, space, nextOffset, typed, loadSite, depth + 1);
                            }
                        } catch (ArithmeticException e) {
                            reasons.add("slot_offset_overflow");
                        }
                    }
                    case PcodeOp.PTRADD -> {
                        Long index = constant(input(value, definition, 1), depth + 1,
                            Collections.newSetFromMap(new IdentityHashMap<>()));
                        Long scale = constant(input(value, definition, 2), depth + 1,
                            Collections.newSetFromMap(new IdentityHashMap<>()));
                        if (index == null || scale == null) {
                            reasons.add("dynamic_slot_offset");
                            return;
                        }
                        try {
                            long addition = Math.multiplyExact(index, scale);
                            long nextOffset = Math.addExact(offset, addition);
                            if (offsetFits(op, nextOffset)) {
                                pointer(input(value, definition, 0), space, nextOffset,
                                    typed, loadSite, depth + 1);
                            }
                        } catch (ArithmeticException e) {
                            reasons.add("slot_offset_overflow");
                        }
                    }
                    case PcodeOp.INDIRECT -> reasons.add("indirect_side_effect");
                    // A vptr loaded from an object has unknown runtime identity.
                    // Never use an earlier STORE or the image's memory snapshot
                    // as proof of its value at this call.
                    case PcodeOp.LOAD -> candidate(offset, typed, loadSite);
                    default -> reasons.add("unsupported_base_operation_" + op.getMnemonic().toLowerCase(java.util.Locale.ROOT));
                }
            } finally {
                path.remove(value.node());
            }
        }

        private Long constant(Value value, int depth, Set<Varnode> visited) throws CancelledException {
            session.monitor().checkCancelled();
            if (++steps > MAX_STEPS || depth > MAX_DEPTH) {
                reasons.add("trace_limit");
                return null;
            }
            if (value.node() == null || !visited.add(value.node())) return null;
            try {
                if (value.node().getSize() < 1 || value.node().getSize() > 8) {
                    reasons.add("unsupported_scalar_width");
                    return null;
                }
                if (value.node().isConstant()) return signed(value.node());
                Definition definition = definition(value);
                if (definition == null) return null;
                PcodeOp op = definition.operation();
                int opcode = op.getOpcode();
                if ((opcode == PcodeOp.COPY || opcode == PcodeOp.CAST) && sameWidth(op)) {
                    return constant(input(value, definition, 0), depth + 1, visited);
                }
                if (opcode != PcodeOp.INT_ADD && opcode != PcodeOp.INT_SUB
                        && opcode != PcodeOp.INT_MULT && opcode != PcodeOp.INT_LEFT) return null;
                Long left = constant(input(value, definition, 0), depth + 1, visited);
                Long right = constant(input(value, definition, 1), depth + 1, visited);
                if (left == null || right == null) return null;
                if (op.getOutput() == null || op.getOutput().getSize() < 1
                        || op.getOutput().getSize() > 8) {
                    reasons.add("unsupported_scalar_width");
                    return null;
                }
                int bits = op.getOutput().getSize() * 8;
                // P-code integers are bitvectors. Java's modulo-64 arithmetic,
                // followed by the native output-width truncation, also preserves
                // wrapping 32-bit arithmetic in raw instruction p-code.
                long result = switch (opcode) {
                    case PcodeOp.INT_ADD -> left + right;
                    case PcodeOp.INT_SUB -> left - right;
                    case PcodeOp.INT_MULT -> left * right;
                    default -> right < 0 || right >= bits ? 0L : left << right;
                };
                return signed(result, bits);
            } finally {
                visited.remove(value.node());
            }
        }

        private boolean offsetFits(PcodeOp operation, long offset) {
            Varnode output = operation.getOutput();
            if (output == null || output.getSize() < 1 || output.getSize() > 8) {
                reasons.add("unsupported_pointer_width");
                return false;
            }
            if (signed(offset, output.getSize() * 8) != offset) {
                // Affine bases are not scalar constants: modular pointer wrap
                // needs additional address-space reasoning. Retain uncertainty
                // instead of silently excluding a matching wrapped offset.
                reasons.add("slot_offset_width_overflow");
                return false;
            }
            return true;
        }

        private void concrete(Address base, long offset, Address loadSite) {
            if (base.getAddressSpace().getAddressableUnitSize() != 1) {
                reasons.add("unsupported_addressable_unit_size");
                return;
            }
            try {
                Address slot = base.addNoWrap(offset);
                if (!slot.getAddressSpace().equals(addressPoint.getAddressSpace())) return;
                long relative = slot.subtract(addressPoint);
                if (slotOffsets.contains(relative)) {
                    recordCandidate(relative, "table_value", null, loadSite);
                }
                // A concrete different address is contrary evidence. It must
                // not fall back to the weaker offset/type candidate paths.
            } catch (ghidra.program.model.address.AddressOverflowException | ArithmeticException e) {
                reasons.add("slot_address_overflow");
            }
        }

        private void candidate(long offset, boolean typed, Address loadSite) {
            if (!slotOffsets.contains(offset)) return;
            recordCandidate(offset, typed ? "table_type" : "slot_offset", typed ? tableType : null, loadSite);
        }

        private void recordCandidate(long offset, String evidence, DataType type, Address loadSite) {
            Candidate old = matches.get(offset);
            Set<Address> sites = old == null ? new LinkedHashSet<>() : old.loadSites();
            if (loadSite != null && !sites.contains(loadSite)) {
                if (sites.size() < MAX_LOAD_SITES) sites.add(loadSite);
                else reasons.add("load_site_limit");
            }
            if (old == null || rank(evidence) > rank(old.evidence())) {
                matches.put(offset, new Candidate(offset, evidence, type, sites));
            }
        }

        private void finish() throws CancelledException {
            if (merged && (!matches.isEmpty() || !reasons.isEmpty())) reasons.add("merged_flow_alternatives");
            for (Candidate candidate : matches.values()) {
                session.monitor().checkCancelled();
                String evidence = merged ? "slot_offset" : candidate.evidence();
                JsonObject row = identity(site);
                row.addProperty("slot_offset", candidate.offset());
                row.addProperty("evidence", evidence);
                JsonArray loads = new JsonArray();
                for (Address load : candidate.loadSites()) loads.add(AddressCodec.format(load));
                row.add("slot_load_sites", loads);
                row.addProperty("table_address", evidence.equals("table_value")
                    ? AddressCodec.format(addressPoint) : null);
                row.addProperty("table_type", evidence.equals("table_type")
                    ? candidate.type().getPathName() : null);
                row.addProperty("table_type_id", evidence.equals("table_type")
                    ? Long.toString(manager.getID(candidate.type())) : null);
                if (merged) {
                    row.addProperty("reason", "merged_flow_alternatives");
                } else if (evidence.equals("table_type")) {
                    row.addProperty("reason", "static_table_type_only");
                    reasons.add("runtime_table_identity_unknown");
                } else if (evidence.equals("slot_offset")) {
                    row.addProperty("reason", "table_identity_unknown");
                    reasons.add("table_identity_unknown");
                }
                calls.add(row);
            }
            for (String reason : reasons) {
                session.monitor().checkCancelled();
                JsonObject row = identity(site);
                row.addProperty("reason", reason);
                unresolved.add(row);
            }
        }
    }

    private Definition definition(Value value) throws CancelledException {
        if (value.raw() == null) {
            PcodeOp op = value.node().getDef();
            return op == null ? null : new Definition(op, -1);
        }
        for (int i = value.before() - 1; i >= 0; i--) {
            session.monitor().checkCancelled();
            PcodeOp op = value.raw()[i];
            Varnode output = op.getOutput();
            if (output != null && output.intersects(value.node())) {
                if (output.getSize() == value.node().getSize()
                        && output.getAddress().equals(value.node().getAddress())) {
                    return new Definition(op, i);
                }
                // An intervening partial-register write invalidates an older
                // whole-register definition; it cannot be skipped.
                return null;
            }
        }
        return null;
    }

    private static Value input(Value owner, Definition definition, int index) {
        return new Value(definition.operation().getInput(index), owner.raw(), definition.index());
    }

    private static boolean sameWidth(PcodeOp op) {
        return op.getOutput() != null && op.getInput(0).getSize() == op.getOutput().getSize();
    }

    private static long signed(Varnode value) {
        return signed(value.getOffset(), value.getSize() * 8);
    }

    private static long signed(long value, int bits) {
        return bits >= 64 ? value : value << (64 - bits) >> (64 - bits);
    }

    private boolean tablePointer(Varnode value) throws CancelledException {
        if (tableType == null || value.getHigh() == null) return false;
        DataType type = base(value.getHigh().getDataType());
        if (!(type instanceof Pointer pointer)) return false;
        DataType target = base(pointer.getDataType());
        return target != null && target.getDataTypeManager() == manager
            && tableType.getDataTypeManager() == manager
            && manager.contains(target) && manager.contains(tableType)
            && manager.getID(target) == manager.getID(tableType);
    }

    private DataType base(DataType type) throws CancelledException {
        Set<DataType> visited = Collections.newSetFromMap(new IdentityHashMap<>());
        while (type instanceof TypeDef alias && visited.add(type)) {
            session.monitor().checkCancelled();
            type = alias.getDataType();
        }
        return type;
    }

    private JsonObject identity(Address site) {
        JsonObject row = new JsonObject();
        row.addProperty("caller", function.getName(true));
        row.addProperty("caller_address", AddressCodec.format(function.getEntryPoint()));
        row.addProperty("call_site", AddressCodec.format(site));
        return row;
    }

    private static int rank(String evidence) {
        return evidence.equals("table_value") ? 3 : evidence.equals("table_type") ? 2 : 1;
    }
}
