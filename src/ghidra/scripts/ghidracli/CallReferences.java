package ghidracli;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.exception.CancelledException;
import java.util.ArrayDeque;
import java.util.Collections;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.BiPredicate;

/** Incoming call resolution shared by call search and caller graph traversal. */
final class CallReferences {
    private final ProgramSession session;
    private final AddressResolver addressResolver;

    CallReferences(ProgramSession session, AddressResolver addressResolver) {
        this.session = session;
        this.addressResolver = addressResolver;
    }

    Function resolveTarget(String target) throws CancelledException {
        FunctionManager fm = session.program().getFunctionManager();
        ReferenceManager refs = session.program().getReferenceManager();
        Address explicit = addressResolver.parseAddress(target);
        Set<Address> candidates = explicit == null ? addressResolver.namedAddresses(target)
            : Set.of(explicit);
        Map<Address, Function> functions = new LinkedHashMap<>();
        for (Address candidate : candidates) {
            session.monitor().checkCancelled();
            Function function = fm.getFunctionAt(candidate);
            if (function == null) function = fm.getFunctionContaining(candidate);
            // Import labels may name the pointer slot instead of the external function.
            if (function == null) {
                for (Reference ref : refs.getReferencesFrom(candidate)) {
                    session.monitor().checkCancelled();
                    if (ref.isExternalReference()) {
                        Function external = fm.getFunctionAt(ref.getToAddress());
                        if (external != null) functions.put(external.getEntryPoint(), external);
                    }
                }
                continue;
            }
            Function canonical = function.isThunk() ? function.getThunkedFunction(true) : function;
            if (canonical != null) functions.put(canonical.getEntryPoint(), canonical);
        }
        if (functions.size() > 1) throw new IllegalArgumentException("Ambiguous function target '" + target
            + "' at " + functions.keySet() + "; use an explicit address");
        return functions.isEmpty() ? null : functions.values().iterator().next();
    }

    /** Visit each call site once; a false visitor result stops the scan immediately. */
    boolean visitCallsTo(Function callee, BiPredicate<Reference, Address> visitor)
            throws CancelledException {
        ReferenceManager refs = session.program().getReferenceManager();
        Listing listing = session.program().getListing();
        Deque<Address> pending = new ArrayDeque<>();
        Set<Address> visited = new HashSet<>();
        Set<Address> sites = new HashSet<>();
        pending.add(callee.getEntryPoint());
        Address[] thunks = callee.getFunctionThunkAddresses(true);
        if (thunks != null) Collections.addAll(pending, thunks);
        while (!pending.isEmpty()) {
            session.monitor().checkCancelled();
            Address destination = pending.removeFirst();
            if (!visited.add(destination)) continue;
            for (Reference ref : refs.getReferencesTo(destination)) {
                session.monitor().checkCancelled();
                Address from = ref.getFromAddress();
                Instruction instruction = listing.getInstructionAt(from);
                RefType type = ref.getReferenceType();
                if (isCallSite(instruction, ref)) {
                    if (sites.add(from) && !visitor.test(ref, destination)) return false;
                } else if (instruction == null) {
                    Data data = listing.getDataAt(from);
                    if (data != null && data.isPointer()
                            && (type == RefType.DATA || type == RefType.INDIRECTION
                                || ref.isExternalReference())) {
                        pending.addLast(from);
                    }
                }
            }
        }
        return true;
    }

    private boolean isCallSite(Instruction instruction, Reference ref) {
        if (instruction == null) return false;
        RefType type = ref.getReferenceType();
        if (type.isCall()) {
            return instruction.getFlowType().isCall() || (type.isOverride() && ref.isPrimary());
        }
        // PARAM describes an argument even when attached to a call instruction.
        // A known computed-call operand can instead have a READ/DATA reference.
        return instruction.getFlowType().isCall() && instruction.getFlowType().isComputed()
            && (type.isRead() || type == RefType.DATA || type == RefType.INDIRECTION);
    }
}
