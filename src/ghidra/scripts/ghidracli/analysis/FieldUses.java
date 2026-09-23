package ghidracli.analysis;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.app.decompiler.ClangFieldToken;
import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangVariableToken;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Union;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.exception.CancelledException;
import ghidracli.query.AddressCodec;
import ghidracli.session.ProgramSession;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Native field identities and access events from one complete decompilation. */
final class FieldUses {
    record Findings(JsonArray uses, JsonArray unresolved) {}

    private record FieldReference(PcodeOp operation, Varnode variable, boolean bitField) {}
    private record PointerValue(Varnode value, long offset, long indexScale) {}

    private final ProgramSession session;
    private final Function function;
    private final DataTypeComponent field;
    private final Composite parent;
    private final DataTypeManager manager;
    private final long parentId;
    private final HighPcodeModel model;
    private final JsonArray uses = new JsonArray();
    private final JsonArray unresolved = new JsonArray();
    private final Map<PcodeOp, Set<String>> emitted = new IdentityHashMap<>();
    private final Map<PcodeOp, Set<String>> diagnostics = new IdentityHashMap<>();
    private final Set<PcodeOp> nativeMembers = Collections.newSetFromMap(new IdentityHashMap<>());
    private final List<FieldReference> unclassified = new ArrayList<>();

    private FieldUses(ProgramSession session, Function function, DecompileResults results,
            DataTypeComponent field) throws CancelledException {
        this.session = session;
        this.function = function;
        this.field = field;
        parent = (Composite) field.getParent();
        manager = session.program().getDataTypeManager();
        parentId = manager.getID(parent);
        if (parent.getDataTypeManager() != manager || !manager.contains(parent)) {
            throw new IllegalArgumentException("Field parent must be registered in the current program");
        }
        model = HighPcodeModel.build(results.getHighFunction(), session.monitor());
    }

    static Findings find(ProgramSession session, Function function, DecompileResults results,
            DataTypeComponent field) throws Exception {
        FieldUses scan = new FieldUses(session, function, results, field);
        for (FieldReference reference : scan.references(results.getCCodeMarkup())) {
            session.monitor().checkCancelled();
            scan.reference(reference);
        }
        scan.partialVariables();
        scan.ambiguousMemory();
        for (FieldReference reference : scan.unclassified) {
            session.monitor().checkCancelled();
            if (!scan.emitted.containsKey(reference.operation())) {
                scan.emit(reference.operation(), "unknown",
                    reference.bitField() ? "clang_bit_field" : "clang_field", null, null);
                scan.diagnostic(reference.operation(), "field_access_unclassified");
            }
        }
        session.monitor().checkCancelled();
        return new Findings(scan.uses, scan.unresolved);
    }

    private boolean sameParent(DataType candidate) throws CancelledException {
        candidate = base(candidate);
        return candidate != null && candidate.getDataTypeManager() == manager
            && manager.contains(candidate) && manager.getID(candidate) == parentId;
    }

    private DataType base(DataType type) throws CancelledException {
        if (!(type instanceof TypeDef)) return type;
        Set<DataType> visited = Collections.newSetFromMap(new IdentityHashMap<>());
        while (type instanceof TypeDef alias && visited.add(type)) {
            session.monitor().checkCancelled();
            type = alias.getDataType();
        }
        return type;
    }

    private List<FieldReference> references(ClangNode root) throws Exception {
        List<FieldReference> references = new ArrayList<>();
        if (root == null) {
            diagnostic(null, "missing_c_markup");
            return references;
        }
        ArrayDeque<ClangNode> pending = new ArrayDeque<>();
        pending.push(root);
        // Native partial-symbol printing emits the base variable immediately before
        // its member chain. Keep the native varref, never parse generated C text.
        Map<PcodeOp, Varnode> precedingVariables = new IdentityHashMap<>();
        while (!pending.isEmpty()) {
            session.monitor().checkCancelled();
            ClangNode node = pending.pop();
            if (node instanceof ClangVariableToken variable && variable.getVarnode() != null) {
                precedingVariables.put(variable.getPcodeOp(), variable.getVarnode());
            }
            if (node instanceof ClangFieldToken token && sameParent(token.getDataType())) {
                // Despite getOffset's name, union field IDs are component ordinals:
                // PcodeDataTypeManager.encodeUnion writes ATTRIB_ID for each member.
                int identifier = parent instanceof Union ? field.getOrdinal() : field.getOffset();
                if (token.getPcodeOp() != null && (!field.isBitFieldComponent() || parent instanceof Union)) {
                    nativeMembers.add(token.getPcodeOp());
                }
                if (token.getOffset() == identifier) {
                    if (field.isBitFieldComponent() && !(parent instanceof Union)) {
                        diagnostic(token.getPcodeOp(), "bit_field_identity_unavailable");
                    } else {
                        references.add(new FieldReference(token.getPcodeOp(),
                            precedingVariables.get(token.getPcodeOp()), false));
                    }
                }
            } else if (node instanceof ClangToken token
                    && node.getClass().getName().equals("ghidra.app.decompiler.ClangBitFieldToken")) {
                // This native token was added after Ghidra 11. Keep the bridge loadable
                // there; byte-storage overlap alone never identifies a bit-field.
                DataTypeComponent component = bitFieldComponent(token);
                if (component != null && sameParent(component.getParent())) {
                    PcodeOp op = token.getPcodeOp();
                    recordBitFieldStorage(op);
                    if (component.getOrdinal() == field.getOrdinal()) {
                        references.add(new FieldReference(op, precedingVariables.get(op), true));
                    }
                }
            }
            for (int i = node.numChildren() - 1; i >= 0; i--) pending.push(node.Child(i));
        }
        return references;
    }

    private void recordBitFieldStorage(PcodeOp op) {
        if (op == null) return;
        nativeMembers.add(op);
        if (op.getOpcode() == PcodeOp.STORE) {
            PcodeOp insert = op.getInput(2).getDef();
            if (insert == null || !insert.getMnemonic().equals("INSERT")) return;
            nativeMembers.add(insert);
            op = insert;
        }
        String mnemonic = op.getMnemonic();
        if (mnemonic.equals("ZPULL") || mnemonic.equals("SPULL") || mnemonic.equals("INSERT")) {
            // INSERT's prior LOAD preserves the neighboring bits; it is not
            // evidence that those neighboring fields were semantically read.
            PcodeOp load = op.getInput(0).getDef();
            if (load != null && load.getOpcode() == PcodeOp.LOAD) nativeMembers.add(load);
        }
    }

    private static DataTypeComponent bitFieldComponent(ClangToken token) throws Exception {
        try {
            return (DataTypeComponent) token.getClass().getMethod("getComponent").invoke(token);
        } catch (InvocationTargetException e) {
            if (e.getCause() instanceof Exception cause) throw cause;
            throw e;
        }
    }

    private void reference(FieldReference reference) throws CancelledException {
        PcodeOp op = reference.operation();
        if (op == null) {
            emit(null, "unknown", "clang_field", null, null);
            diagnostic(null, "field_operation_unavailable");
            return;
        }
        if (reference.bitField()) {
            // Ghidra's native bit-field printer attaches read tokens to PULL and
            // write tokens to INSERT/STORE, including direct register-backed fields.
            String mnemonic = op.getMnemonic();
            if (mnemonic.equals("ZPULL") || mnemonic.equals("SPULL")) {
                emit(op, "read", "clang_bit_field", op, null);
                return;
            }
            if (mnemonic.equals("INSERT") || op.getOpcode() == PcodeOp.STORE) {
                emit(op, "write", "clang_bit_field", op, null);
                return;
            }
        }
        if (op.getOpcode() == PcodeOp.PTRSUB && op.getOutput() != null) {
            pointerUses(op, "clang_field");
            return;
        }
        boolean classified = false;
        if (op.getOpcode() == PcodeOp.SUBPIECE && extractsField(op)) {
            emit(op, "read", "clang_field", op, size(op.getOutput()));
            classified = true;
        }
        Varnode variable = reference.variable();
        if (fieldVariable(variable) && !bookkeeping(op)) {
            if (op.getOutput() == variable && !projection(op, variable.getHigh().getSymbol())) {
                emit(op, "write", "clang_field", op, size(variable));
                classified = true;
            }
            for (int i = 0; i < op.getNumInputs(); i++) {
                if (op.getInput(i) == variable && !HighPcodeModel.isOperationReference(op, i)
                        && !HighPcodeModel.isSpaceReference(op, i)) {
                    emit(op, "read", "clang_field", op, size(variable));
                    classified = true;
                }
            }
        }
        if (!classified) {
            unclassified.add(reference);
        }
    }

    private boolean fieldVariable(Varnode node) throws CancelledException {
        if (node == null || node.getHigh() == null) return false;
        HighVariable variable = node.getHigh();
        if (sameParent(variable.getDataType())) return true;
        HighSymbol symbol = variable.getSymbol();
        return symbol != null && variable.getOffset() >= 0
            && fieldAt(symbol.getDataType(), variable.getOffset(), node.getSize()) != 0;
    }

    private boolean extractsField(PcodeOp op) throws CancelledException {
        Varnode source = op.getInput(0);
        HighVariable variable = source.getHigh();
        if (variable == null || !op.getInput(1).isConstant()) return false;
        long offset = op.getInput(1).getOffset();
        int width = size(op.getOutput());
        if (session.program().getLanguage().isBigEndian()) offset = source.getSize() - width - offset;
        if (fieldAt(variable.getDataType(), offset, width) != 0) return true;
        HighSymbol symbol = variable.getSymbol();
        return symbol != null && variable.getOffset() >= 0
            && fieldAt(symbol.getDataType(), offset + variable.getOffset(), width) != 0;
    }

    private void pointerUses(PcodeOp origin, String source) throws CancelledException {
        ArrayDeque<PointerValue> pending = new ArrayDeque<>();
        pending.add(new PointerValue(origin.getOutput(), 0, 0));
        Set<Varnode> visited = Collections.newSetFromMap(new IdentityHashMap<>());
        boolean classified = false;
        while (!pending.isEmpty()) {
            session.monitor().checkCancelled();
            PointerValue pointer = pending.removeFirst();
            if (!visited.add(pointer.value())) continue;
            HighPcodeModel.Value value = model.valueIndex.get(pointer.value());
            if (value == null) continue;
            for (HighPcodeModel.Use use : value.uses) {
                session.monitor().checkCancelled();
                PcodeOp op = use.operation.source;
                int opcode = op.getOpcode();
                if ((opcode == PcodeOp.COPY || opcode == PcodeOp.CAST) && use.slot == 0
                        && op.getOutput() != null && op.getOutput().getSize() == pointer.value().getSize()) {
                    pending.add(new PointerValue(op.getOutput(), pointer.offset(), pointer.indexScale()));
                    continue;
                }
                if ((opcode == PcodeOp.LOAD || opcode == PcodeOp.STORE) && use.slot == 1) {
                    int width = opcode == PcodeOp.LOAD ? size(op.getOutput()) : size(op.getInput(2));
                    if (withinField(pointer, width, op)) {
                        emit(op, opcode == PcodeOp.LOAD ? "read" : "write", source, origin, width);
                    } else {
                        emit(origin, "address", source, origin, null);
                        diagnostic(op, "memory_access_extends_beyond_field");
                    }
                    classified = true;
                    continue;
                }
                if ((opcode == PcodeOp.PTRSUB || opcode == PcodeOp.PTRADD || opcode == PcodeOp.INT_ADD)
                        && use.slot == 0 && op.getOutput() != null) {
                    PointerValue advanced = advance(pointer, op);
                    if (advanced != null) {
                        pending.add(advanced);
                        continue;
                    }
                }
                // A call argument, returned pointer, stored pointer or other use
                // consumes the field's address; it does not prove a pointee read.
                // Do not follow phi nodes: another incoming pointer may name a
                // different member. Preserve that incompleteness explicitly.
                if (opcode == PcodeOp.MULTIEQUAL || opcode == PcodeOp.INDIRECT) {
                    diagnostic(op, "field_pointer_merges_with_other_values");
                }
                emit(origin, "address", source, origin, null);
                classified = true;
            }
        }
        if (!classified) emit(origin, "address", source, origin, null);
    }

    private PointerValue advance(PointerValue pointer, PcodeOp op) throws CancelledException {
        Varnode displacement = op.getInput(1);
        if (!displacement.isConstant()) {
            // Native PTRADD identifies indexing. Only a selected array member
            // permits an unknown element index without losing its member identity.
            if (op.getOpcode() == PcodeOp.PTRADD
                    && base(field.getDataType()) instanceof Array
                    && op.getInput(2).isConstant()
                    && op.getInput(2).getOffset() > 0
                    && (pointer.indexScale() == 0 || pointer.indexScale() == op.getInput(2).getOffset())) {
                return new PointerValue(op.getOutput(), pointer.offset(), op.getInput(2).getOffset());
            }
            return null;
        }
        long delta = displacement.getOffset();
        try {
            if (op.getOpcode() == PcodeOp.PTRADD) {
                if (!op.getInput(2).isConstant()) return null;
                delta = Math.multiplyExact(delta, op.getInput(2).getOffset());
            }
            long offset = Math.addExact(pointer.offset(), delta);
            if (offset < 0 || offset >= field.getLength()) return null;
            return new PointerValue(op.getOutput(), offset, pointer.indexScale());
        } catch (ArithmeticException e) {
            return null;
        }
    }

    private boolean withinField(PointerValue pointer, int width, PcodeOp memory) throws CancelledException {
        // P-code arithmetic uses addressable units; component offsets/sizes use
        // bytes. The LOAD/STORE space retains the native word size even when the
        // decoded Java Pointer datatype does not retain that information.
        int unit = addressUnit(memory);
        try {
            long offset = Math.multiplyExact(pointer.offset(), unit);
            if (pointer.indexScale() != 0 && (!(base(field.getDataType()) instanceof Array array)
                    || Math.multiplyExact(pointer.indexScale(), unit) != array.getElementLength())) return false;
            return width > 0 && offset >= 0 && offset <= (long) field.getLength() - width;
        } catch (ArithmeticException e) {
            return false;
        }
    }

    private int addressUnit(PcodeOp memory) {
        return session.program().getAddressFactory()
            .getAddressSpace((int) memory.getInput(0).getOffset()).getAddressableUnitSize();
    }

    private void partialVariables() throws CancelledException {
        for (HighPcodeModel.Value value : model.values) {
            session.monitor().checkCancelled();
            Varnode node = value.source;
            HighVariable variable = node.getHigh();
            if (variable == null || variable.getSymbol() == null || variable.getOffset() < 0) continue;
            HighSymbol symbol = variable.getSymbol();
            // Whole aggregate copies do not establish an individual field access.
            if (variable.getOffset() == 0 && node.getSize() >= symbol.getSize()) continue;
            int match = fieldAt(symbol.getDataType(), variable.getOffset(), node.getSize());
            if (match == 0) continue;
            PcodeOp definition = node.getDef();
            if (!model.operationIndex.containsKey(definition)) definition = null;
            if (match < 0) {
                if (definition != null && !nativeMembers.contains(definition)
                        && !bookkeeping(definition) && !projection(definition, symbol)) {
                    diagnostic(definition, "overlapping_field_storage");
                }
                for (HighPcodeModel.Use use : value.uses) {
                    if (!nativeMembers.contains(use.operation.source) && !bookkeeping(use.operation.source)) {
                        diagnostic(use.operation.source, "overlapping_field_storage");
                    }
                }
                continue;
            }
            if (definition != null && !bookkeeping(definition) && !projection(definition, symbol)) {
                emit(definition, "write", "high_symbol", null, node.getSize());
            }
            for (HighPcodeModel.Use use : value.uses) {
                session.monitor().checkCancelled();
                // A spacebase PTRSUB carries a symbol on its constant offset.
                // That constant denotes the member's address, not its value.
                if (use.operation.source.getOpcode() == PcodeOp.PTRSUB && use.slot == 1) {
                    pointerUses(use.operation.source, "high_symbol");
                    continue;
                }
                if (!bookkeeping(use.operation.source)) {
                    emit(use.operation.source, "read", "high_symbol", null, node.getSize());
                }
            }
        }
    }

    private void ambiguousMemory() throws CancelledException {
        if (!(parent instanceof Union) && !field.isBitFieldComponent()) return;
        for (HighPcodeModel.Operation operation : model.operations) {
            session.monitor().checkCancelled();
            PcodeOp op = operation.source;
            if (nativeMembers.contains(op)) continue;
            if (op.getOpcode() != PcodeOp.LOAD && op.getOpcode() != PcodeOp.STORE) continue;
            int width = op.getOpcode() == PcodeOp.LOAD ? size(op.getOutput()) : size(op.getInput(2));
            if (ambiguousPointer(op.getInput(1), width, addressUnit(op))) {
                diagnostic(op, "overlapping_field_storage");
            }
        }
    }

    private boolean ambiguousPointer(Varnode node, int width, int unit) throws CancelledException {
        Set<Varnode> visited = Collections.newSetFromMap(new IdentityHashMap<>());
        long offset = 0;
        while (node != null && visited.add(node)) {
            session.monitor().checkCancelled();
            PcodeOp definition = node.getDef();
            // Native union/bit-field selection is stronger than byte overlap,
            // including selection of a different member than the requested one.
            if (nativeMembers.contains(definition)) return false;
            DataType type = node.getHigh() == null ? null : base(node.getHigh().getDataType());
            if (type instanceof Pointer pointer && fieldAt(pointer.getDataType(), offset, width) < 0) {
                return true;
            }
            if (definition == null) return false;
            int opcode = definition.getOpcode();
            if (opcode == PcodeOp.COPY || opcode == PcodeOp.CAST) {
                node = definition.getInput(0);
                continue;
            }
            if (opcode != PcodeOp.PTRSUB && opcode != PcodeOp.PTRADD && opcode != PcodeOp.INT_ADD) return false;
            Varnode displacement = definition.getInput(1);
            if (!displacement.isConstant()) return false;
            try {
                long delta = displacement.getOffset();
                if (opcode == PcodeOp.PTRADD) {
                    if (!definition.getInput(2).isConstant()) return false;
                    delta = Math.multiplyExact(delta, definition.getInput(2).getOffset());
                }
                offset = Math.addExact(offset, Math.multiplyExact(delta, unit));
            } catch (ArithmeticException e) {
                return false;
            }
            node = definition.getInput(0);
        }
        return false;
    }

    /** 1 is a proven field; -1 is overlapping storage; 0 is a different field. */
    private int fieldAt(DataType type, long offset, int width) throws CancelledException {
        Set<DataType> visited = Collections.newSetFromMap(new IdentityHashMap<>());
        while (type != null && visited.add(type)) {
            session.monitor().checkCancelled();
            type = base(type);
            if (sameParent(type)) {
                if (parent instanceof Union || field.isBitFieldComponent()) {
                    // A wider storage read may begin before this bit-field's
                    // byte. Overlap is uncertainty, never a positive member use.
                    return width > 0 && offset < (long) field.getOffset() + field.getLength()
                        && offset + width > field.getOffset() ? -1 : 0;
                }
                long relative = offset - field.getOffset();
                if (relative < 0 || relative >= field.getLength()) return 0;
                return width > 0 && relative <= (long) field.getLength() - width ? 1 : 0;
            }
            if (type instanceof Array array) {
                int size = array.getElementLength();
                if (size <= 0 || offset < 0 || offset >= array.getLength()) return 0;
                offset %= size;
                if (offset + width > size) return 0;
                type = array.getDataType();
            } else if (type instanceof Structure structure) {
                if (offset < 0 || offset > Integer.MAX_VALUE) return 0;
                DataTypeComponent component = structure.getComponentContaining((int) offset);
                if (component == null || component.isBitFieldComponent()
                        || offset + width > (long) component.getOffset() + component.getLength()) return 0;
                offset -= component.getOffset();
                type = component.getDataType();
            } else {
                return 0;
            }
        }
        return 0;
    }

    private static boolean bookkeeping(PcodeOp op) {
        return op.getOpcode() == PcodeOp.MULTIEQUAL || op.getOpcode() == PcodeOp.INDIRECT;
    }

    private boolean projection(PcodeOp op, HighSymbol symbol) {
        // Decompilation inserts SUBPIECEs to expose by-value aggregate components.
        // Defining that SSA fragment does not write the containing parameter/local.
        if (symbol == null || op.getNumInputs() == 0 || op.getInput(0).getHigh() == null
                || op.getInput(0).getHigh().getSymbol() != symbol
                || op.getOutput() == null || op.getOutput().getHigh() == null) return false;
        if (op.getOpcode() == PcodeOp.SUBPIECE && op.getInput(1).isConstant()) {
            long offset = op.getInput(1).getOffset();
            if (session.program().getLanguage().isBigEndian()) {
                offset = op.getInput(0).getSize() - op.getOutput().getSize() - offset;
            }
            return Math.max(0, op.getInput(0).getHigh().getOffset()) + offset
                == op.getOutput().getHigh().getOffset();
        }
        return (op.getOpcode() == PcodeOp.COPY || op.getOpcode() == PcodeOp.CAST)
            && op.getInput(0).getSize() == op.getOutput().getSize()
            && op.getInput(0).getHigh().getOffset() == op.getOutput().getHigh().getOffset();
    }

    private static int size(Varnode value) { return value == null ? 0 : value.getSize(); }

    private JsonObject location(PcodeOp op) {
        JsonObject row = new JsonObject();
        row.addProperty("function", function.getName(true));
        row.addProperty("function_address", AddressCodec.format(function.getEntryPoint()));
        row.addProperty("instruction_address", op == null ? null : AddressCodec.format(op.getSeqnum().getTarget()));
        row.addProperty("sequence", op == null ? null : op.getSeqnum().getTime());
        return row;
    }

    private void emit(PcodeOp op, String access, String source, PcodeOp fieldOperation, Integer width) {
        if (!emitted.computeIfAbsent(op, key -> new HashSet<>()).add(access)) return;
        JsonObject row = location(op);
        row.addProperty("access", access);
        JsonObject evidence = new JsonObject();
        evidence.addProperty("source", source);
        evidence.addProperty("mnemonic", op == null ? null : op.getMnemonic());
        if (fieldOperation != null && fieldOperation != op) {
            evidence.addProperty("field_instruction_address", AddressCodec.format(fieldOperation.getSeqnum().getTarget()));
            evidence.addProperty("field_sequence", fieldOperation.getSeqnum().getTime());
            evidence.addProperty("field_mnemonic", fieldOperation.getMnemonic());
        }
        if (width != null) evidence.addProperty("size", width);
        row.add("evidence", evidence);
        uses.add(row);
    }

    private void diagnostic(PcodeOp op, String reason) {
        if (!diagnostics.computeIfAbsent(op, key -> new HashSet<>()).add(reason)) return;
        JsonObject row = location(op);
        row.addProperty("reason", reason);
        row.addProperty("containing_type_path", parent.getPathName());
        unresolved.add(row);
    }
}
