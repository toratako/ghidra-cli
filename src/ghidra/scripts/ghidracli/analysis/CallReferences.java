package ghidracli.analysis;

import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.exception.CancelledException;
import ghidracli.listing.InstructionFlow;
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

  record Call(
      Address site,
      Function caller,
      Endpoint callee,
      Address destination,
      Address via,
      RefType type) {
    JsonObject toJson() {
      JsonObject row = new JsonObject();
      row.addProperty("call_site", AddressCodec.format(site));
      row.addProperty("caller", caller == null ? null : caller.getName());
      row.addProperty(
          "caller_address", caller == null ? null : AddressCodec.format(caller.getEntryPoint()));
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
    Set<Address> candidates =
        explicit == null ? addressResolver.namedAddresses(target.trim()) : Set.of(explicit);
    Map<Address, Endpoint> endpoints = new LinkedHashMap<>();
    for (Address candidate : candidates) {
      // A recorded executable target is stronger evidence than pointer
      // data at the same address, just as an exact Function is.
      boolean followPointers =
          session.program().getFunctionManager().getFunctionAt(candidate) == null
              && !hasCallTargetReference(candidate);
      for (Endpoint endpoint : destinations(candidate, followPointers).values()) {
        endpoints.put(endpoint.address(), endpoint);
      }
    }
    if (endpoints.size() > 1)
      throw new IllegalArgumentException(
          "Ambiguous call target '"
              + target
              + "' at "
              + endpoints.keySet().stream().map(AddressCodec::format).toList()
              + "; use a 0x-prefixed address");
    return endpoints.isEmpty() ? null : endpoints.values().iterator().next();
  }

  private boolean hasCallTargetReference(Address address) throws CancelledException {
    for (Reference reference : session.program().getReferenceManager().getReferencesTo(address)) {
      session.monitor().checkCancelled();
      if (reference.getReferenceType().isCall()
          && isCallSite(
              session.program().getListing().getInstructionAt(reference.getFromAddress()),
              reference)) return true;
    }
    return false;
  }

  /**
   * Operand evidence and target aliases may follow pointers; call flow targets execute directly.
   */
  private Map<Address, Endpoint> destinations(Address start, boolean followPointers)
      throws CancelledException {
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
      if (followPointers) {
        for (Reference ref : refs.getReferencesFrom(address)) {
          session.monitor().checkCancelled();
          if (isPointerReference(ref)) {
            pending.addLast(ref.getToAddress());
            followed = true;
          }
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
    RefType type = ref.getReferenceType();
    if (type != RefType.DATA && type != RefType.INDIRECTION && !ref.isExternalReference()) {
      return false;
    }
    Data data = session.program().getListing().getDefinedDataContaining(ref.getFromAddress());
    if (data == null) return false;
    long offset = ref.getFromAddress().subtract(data.getMinAddress());
    if (offset > Integer.MAX_VALUE) return false;
    Data primitive = data.getPrimitiveAt((int) offset);
    return primitive != null
        && primitive.isPointer()
        && primitive.getAddress().equals(ref.getFromAddress());
  }

  /**
   * Keep distinct landing addresses, even within one callee, but deduplicate slot/flow evidence.
   */
  private Map<Address, Call> callsAt(Address site) throws CancelledException {
    Instruction instruction = session.program().getListing().getInstructionAt(site);
    Function caller = session.program().getFunctionManager().getFunctionContaining(site);
    Map<Address, Call> calls = new LinkedHashMap<>();
    for (Reference ref : session.program().getReferenceManager().getReferencesFrom(site)) {
      session.monitor().checkCancelled();
      if (!isCallSite(instruction, ref)) continue;
      for (Map.Entry<Address, Endpoint> destination :
          destinations(ref.getToAddress(), !ref.getReferenceType().isCall()).entrySet()) {
        Call call =
            new Call(
                site,
                caller,
                destination.getValue(),
                destination.getKey(),
                ref.getToAddress(),
                ref.getReferenceType());
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
    AddressIterator sites =
        session.program().getReferenceManager().getReferenceSourceIterator(caller.getBody(), true);
    while (sites.hasNext()) {
      session.monitor().checkCancelled();
      for (Call call : callsAt(sites.next()).values()) {
        if (!visitor.test(call)) return false;
      }
    }
    return true;
  }

  private void addDestinations(Function function, Deque<Address> pending)
      throws CancelledException {
    pending.addLast(function.getEntryPoint());
    AddressIterator destinations =
        session
            .program()
            .getReferenceManager()
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
            if (call.callee().address().equals(callee.address()) && !visitor.test(call))
              return false;
          }
        }
      }
    }
    return true;
  }

  private boolean isCallSite(Instruction instruction, Reference ref) throws CancelledException {
    if (instruction == null) return false;
    // Register/stack references identify operand storage, not the runtime
    // code address held there by a computed call.
    Address destination = ref.getToAddress();
    if (!destination.isMemoryAddress() && !destination.isExternalAddress()) return false;
    RefType type = ref.getReferenceType();
    if (type.isCall()) {
      return InstructionFlow.isCallReference(instruction, ref);
    }
    // PARAM describes an argument even when attached to a call instruction.
    if (!instruction.getFlowType().isCall()
        || !instruction.getFlowType().isComputed()
        || !(type.isRead() || type == RefType.DATA || type == RefType.INDIRECTION)) return false;
    // A reference override can turn CALLIND into CALL without changing the
    // Listing flow type. Its old operand read no longer identifies a callee.
    PcodeOp[] operations = InstructionFlow.effectivePcode(instruction);
    for (int i = 0; i < operations.length; i++) {
      session.monitor().checkCancelled();
      if (operations[i].getOpcode() == PcodeOp.CALLIND
          && !isDynamicBase(instruction, ref, operations, i)) return true;
    }
    return false;
  }

  /** An encoded indexed base is not a recorded resolved pointer-slot address. */
  private boolean isDynamicBase(
      Instruction instruction, Reference reference, PcodeOp[] operations, int call)
      throws CancelledException {
    int operand = reference.getOperandIndex();
    if (operand < 0
        || operand >= instruction.getNumOperands()
        || !OperandType.isDynamic(
            instruction.getPrototype().getOpType(operand, instruction.getInstructionContext())))
      return false;
    Address destination = reference.getToAddress();
    boolean encoded = false;
    for (Object object : instruction.getOpObjects(operand)) {
      session.monitor().checkCancelled();
      encoded |=
          object instanceof Address address && address.equals(destination)
              || object instanceof Scalar scalar
                  && (scalar.getUnsignedValue() == destination.getOffset()
                      || scalar.getSignedValue() == destination.getOffset());
    }
    if (!encoded) return false;
    int definition = definition(operations, call, operations[call].getInput(0));
    while (definition >= 0
        && (operations[definition].getOpcode() == PcodeOp.COPY
            || operations[definition].getOpcode() == PcodeOp.CAST)) {
      definition = definition(operations, definition, operations[definition].getInput(0));
    }
    if (definition < 0 || operations[definition].getOpcode() != PcodeOp.LOAD) return false;
    PcodeOp load = operations[definition];
    int addressDefinition = definition(operations, definition, load.getInput(1));
    if (addressDefinition < 0 || operations[addressDefinition].getOpcode() != PcodeOp.INT_ADD)
      return false;
    // Follow only additive address definitions. Sleigh can split base +
    // index + displacement across temporaries; scales and stack constants
    // do not contribute an additive displacement to this LOAD.
    var space =
        session.program().getAddressFactory().getAddressSpace((int) load.getInput(0).getOffset());
    Deque<Integer> pending = new ArrayDeque<>();
    Set<Integer> visited = new HashSet<>();
    pending.add(addressDefinition);
    while (!pending.isEmpty()) {
      session.monitor().checkCancelled();
      int current = pending.removeFirst();
      if (!visited.add(current)) continue;
      for (Varnode input : operations[current].getInputs()) {
        if (input.isConstant()) {
          Address base = space.getTruncatedAddress(input.getOffset(), false);
          base = instruction.getAddress().getAddressSpace().getOverlayAddress(base);
          if (destination.equals(base)) return true;
          continue;
        }
        int source = definition(operations, current, input);
        if (source >= 0
            && (operations[source].getOpcode() == PcodeOp.INT_ADD
                || operations[source].getOpcode() == PcodeOp.COPY
                || operations[source].getOpcode() == PcodeOp.CAST)) pending.addLast(source);
      }
    }
    return false;
  }

  private int definition(PcodeOp[] operations, int before, Varnode value)
      throws CancelledException {
    for (int i = before - 1; i >= 0; i--) {
      session.monitor().checkCancelled();
      if (value.equals(operations[i].getOutput())) return i;
    }
    return -1;
  }
}
