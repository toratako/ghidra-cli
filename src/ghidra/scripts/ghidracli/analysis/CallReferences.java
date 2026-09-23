package ghidracli.analysis;

import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.exception.CancelledException;
import ghidracli.query.AddressCodec;
import ghidracli.query.AddressResolver;
import ghidracli.session.ProgramSession;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;

/** Call-site validation and destination resolution shared by every call graph. */
final class CallReferences {
    record Endpoint(Address address, Function function) {}

    record Call(Address site, Function caller, Endpoint callee, Address destination, Address via, RefType type) {
        JsonObject toJson() {
            JsonObject row = new JsonObject();
            row.addProperty("call_site", AddressCodec.format(site));
            row.addProperty("caller", caller == null ? null : caller.getName());
            row.addProperty("caller_address", caller == null ? null
                : AddressCodec.format(caller.getEntryPoint()));
            row.addProperty("callee", callee.function() == null ? null : callee.function().getName());
            row.addProperty("callee_address", AddressCodec.format(callee.address()));
            row.addProperty("destination", AddressCodec.format(destination));
            row.addProperty("via", AddressCodec.format(via));
            row.addProperty("type", type.toString());
            return row;
        }
    }

    private final ProgramSession session;
    private final AddressResolver addressResolver;

    CallReferences(ProgramSession session, AddressResolver addressResolver) {
        this.session = session;
        this.addressResolver = addressResolver;
    }

    Endpoint canonical(Function function) {
        Function target = function.isThunk() ? function.getThunkedFunction(true) : function;
        if (target == null) target = function;
        return new Endpoint(target.getEntryPoint(), target);
    }

    Endpoint resolveTarget(String target) throws CancelledException {
        Address explicit = addressResolver.parseAddress(target);
        Set<Address> candidates = explicit == null ? addressResolver.namedAddresses(target.trim())
            : Set.of(explicit);
        Map<Address, Endpoint> endpoints = new LinkedHashMap<>();
        for (Address candidate : candidates) {
            for (Endpoint endpoint : destinations(candidate).values()) {
                endpoints.put(endpoint.address(), endpoint);
            }
        }
        if (endpoints.size() > 1) throw new IllegalArgumentException("Ambiguous call target '" + target
            + "' at " + endpoints.keySet().stream().map(AddressCodec::format).toList()
            + "; use a 0x-prefixed address");
        return endpoints.isEmpty() ? null : endpoints.values().iterator().next();
    }

    /** Follow only typed pointer references, retaining known addresses without a Function. */
    private Map<Address, Endpoint> destinations(Address start) throws CancelledException {
        FunctionManager fm = session.program().getFunctionManager();
        ReferenceManager refs = session.program().getReferenceManager();
        Map<Address, Endpoint> endpoints = new LinkedHashMap<>();
        Deque<Address> pending = new ArrayDeque<>();
        Set<Address> visited = new HashSet<>();
        pending.add(start);
        while (!pending.isEmpty()) {
            session.monitor().checkCancelled();
            Address address = pending.removeFirst();
            if (!visited.add(address)) continue;
            Function function = fm.getFunctionAt(address);
            if (function != null) {
                Endpoint endpoint = canonical(function);
                endpoints.put(endpoint.address(), endpoint);
                continue;
            }
            boolean followed = false;
            for (Reference ref : refs.getReferencesFrom(address)) {
                session.monitor().checkCancelled();
                if (isPointerReference(ref)) {
                    pending.addLast(ref.getToAddress());
                    followed = true;
                }
            }
            if (!followed) {
                // Literal pools and pointer tables can lie inside a function body.
                // Resolve typed pointers before using the containing function as metadata.
                function = fm.getFunctionContaining(address);
                Endpoint endpoint = function == null ? new Endpoint(address, null) : canonical(function);
                Address destination = function != null && function.isThunk() ? endpoint.address() : address;
                endpoints.put(destination, endpoint);
            }
        }
        // A pointer cycle still has a known operand address; it is not a resolved function.
        if (endpoints.isEmpty()) endpoints.put(start, new Endpoint(start, null));
        return endpoints;
    }

    private boolean isPointerReference(Reference ref) {
        Data data = session.program().getListing().getDataAt(ref.getFromAddress());
        RefType type = ref.getReferenceType();
        return data != null && data.isPointer()
            && (type == RefType.DATA || type == RefType.INDIRECTION || ref.isExternalReference());
    }

    /** Keep distinct landing addresses, even within one callee, but deduplicate slot/flow evidence. */
    private Map<Address, Call> callsAt(Address site) throws CancelledException {
        Instruction instruction = session.program().getListing().getInstructionAt(site);
        Function caller = session.program().getFunctionManager().getFunctionContaining(site);
        Map<Address, Call> calls = new LinkedHashMap<>();
        for (Reference ref : session.program().getReferenceManager().getReferencesFrom(site)) {
            session.monitor().checkCancelled();
            if (!isCallSite(instruction, ref)) continue;
            for (Map.Entry<Address, Endpoint> destination : destinations(ref.getToAddress()).entrySet()) {
                Call call = new Call(site, caller, destination.getValue(), destination.getKey(),
                    ref.getToAddress(), ref.getReferenceType());
                Call previous = calls.get(destination.getKey());
                // Prefer an explicit call reference over a computed operand's READ/DATA evidence.
                if (previous == null || (!previous.type().isCall() && call.type().isCall())) {
                    calls.put(destination.getKey(), call);
                }
            }
        }
        return calls;
    }

    boolean visitCallsFrom(Function caller, Predicate<Call> visitor) throws CancelledException {
        AddressIterator sites = session.program().getReferenceManager()
            .getReferenceSourceIterator(caller.getBody(), true);
        while (sites.hasNext()) {
            session.monitor().checkCancelled();
            for (Call call : callsAt(sites.next()).values()) {
                if (!visitor.test(call)) return false;
            }
        }
        return true;
    }

    private void addDestinations(Function function, Deque<Address> pending) throws CancelledException {
        pending.addLast(function.getEntryPoint());
        AddressIterator destinations = session.program().getReferenceManager()
            .getReferenceDestinationIterator(function.getBody(), true);
        while (destinations.hasNext()) {
            session.monitor().checkCancelled();
            pending.addLast(destinations.next());
        }
    }

    boolean visitCallsTo(Endpoint callee, Predicate<Call> visitor) throws CancelledException {
        ReferenceManager refs = session.program().getReferenceManager();
        Deque<Address> pending = new ArrayDeque<>();
        Set<Address> visited = new HashSet<>();
        Set<Address> sites = new HashSet<>();
        pending.add(callee.address());
        if (callee.function() != null) {
            addDestinations(callee.function(), pending);
            Address[] thunks = callee.function().getFunctionThunkAddresses(true);
            if (thunks != null) {
                for (Address address : thunks) {
                    session.monitor().checkCancelled();
                    Function thunk = session.program().getFunctionManager().getFunctionAt(address);
                    if (thunk != null) addDestinations(thunk, pending);
                }
            }
        }
        while (!pending.isEmpty()) {
            session.monitor().checkCancelled();
            Address destination = pending.removeFirst();
            if (!visited.add(destination)) continue;
            for (Reference ref : refs.getReferencesTo(destination)) {
                session.monitor().checkCancelled();
                Address from = ref.getFromAddress();
                if (isPointerReference(ref)) {
                    pending.addLast(from);
                } else if (sites.add(from)) {
                    for (Call call : callsAt(from).values()) {
                        if (call.callee().address().equals(callee.address()) && !visitor.test(call)) return false;
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
        return instruction.getFlowType().isCall() && instruction.getFlowType().isComputed()
            && (type.isRead() || type == RefType.DATA || type == RefType.INDIRECTION);
    }
}
