package ghidracli.function;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.CancelledException;
import ghidracli.listing.InstructionFlow;
import ghidracli.query.AddressCodec;
import ghidracli.query.AddressResolver;
import ghidracli.query.ListQuery;
import ghidracli.session.ProgramSession;
import java.util.Map;
import java.util.TreeMap;

import static ghidracli.protocol.JsonProtocol.errorResult;
import static ghidracli.protocol.JsonProtocol.getArgString;

/** Existing call evidence for instruction entries not owned by a defined function. */
public final class FunctionCandidateSearch {
    private static final int EVIDENCE_LIMIT = 5;

    private final ProgramSession session;
    private final AddressResolver resolver;

    public FunctionCandidateSearch(ProgramSession session, AddressResolver resolver) {
        this.session = session;
        this.resolver = resolver;
    }

    public JsonObject handleFindFunctionCandidates(JsonObject args) throws Exception {
        Program program = session.program();
        if (program == null) return errorResult("No program loaded");
        AddressSet scope = new AddressSet(resolver.instructionRange(
            getArgString(args, "start"), getArgString(args, "end")))
            .intersect(program.getMemory().getLoadedAndInitializedAddressSet())
            .intersect(program.getMemory().getExecuteSet());
        long limit = ListQuery.pageArgument(args, "limit");
        AddressIterator destinations = program.getReferenceManager()
            .getReferenceDestinationIterator(scope, true);
        JsonArray results = new JsonArray();
        boolean complete = true;
        while (destinations.hasNext()) {
            session.monitor().checkCancelled();
            if (limit > 0 && results.size() >= limit) {
                complete = false;
                break;
            }
            Address address = destinations.next();
            Instruction instruction = program.getListing().getInstructionAt(address);
            if (instruction == null || instruction.isInDelaySlot()
                    || instruction.getFallFrom() != null
                    || program.getFunctionManager().getFunctionContaining(address) != null) {
                continue;
            }
            Map<Address, Reference> calls = callSites(address);
            if (calls.isEmpty()) continue;
            results.add(candidate(instruction, calls));
        }
        session.monitor().checkCancelled();
        JsonObject result = new JsonObject();
        result.add("results", results);
        result.addProperty("count", results.size());
        result.addProperty("scope", "candidate-starts");
        JsonArray ranges = new JsonArray();
        for (AddressRange range : scope.getAddressRanges()) {
            session.monitor().checkCancelled();
            JsonObject row = new JsonObject();
            row.addProperty("start", AddressCodec.format(range.getMinAddress()));
            row.addProperty("end", AddressCodec.format(range.getMaxAddress()));
            ranges.add(row);
        }
        result.add("ranges", ranges);
        JsonObject scan = new JsonObject();
        scan.addProperty("complete", complete);
        if (!complete) scan.addProperty("stop_reason", "limit");
        result.add("scan", scan);
        return result;
    }

    private Map<Address, Reference> callSites(Address address) throws CancelledException {
        Map<Address, Reference> calls = new TreeMap<>();
        for (Reference reference : session.program().getReferenceManager().getReferencesTo(address)) {
            session.monitor().checkCancelled();
            Instruction source = session.program().getListing()
                .getInstructionAt(reference.getFromAddress());
            // getFallFrom() only finds a nearby predecessor. An explicit
            // fallthrough override can lead here from anywhere in the program.
            if (reference.getReferenceType().isFallthrough() && source != null
                    && address.equals(source.getFallThrough())) {
                calls.clear();
                return calls;
            }
            if (InstructionFlow.isCallReference(source, reference)) {
                calls.putIfAbsent(reference.getFromAddress(), reference);
            }
        }
        return calls;
    }

    private JsonObject candidate(Instruction instruction, Map<Address, Reference> calls)
            throws CancelledException {
        Program program = session.program();
        Address address = instruction.getAddress();
        JsonObject row = new JsonObject();
        row.addProperty("address", AddressCodec.format(address));
        Symbol symbol = program.getSymbolTable().getPrimarySymbol(address);
        if (symbol != null) row.addProperty("name", symbol.getName(true));
        row.addProperty("block", program.getMemory().getBlock(address).getName());
        row.addProperty("instruction", instruction.toString());
        row.addProperty("call_count", calls.size());
        JsonArray evidence = new JsonArray();
        for (Reference reference : calls.values()) {
            session.monitor().checkCancelled();
            if (evidence.size() == EVIDENCE_LIMIT) break;
            JsonObject item = new JsonObject();
            Address from = reference.getFromAddress();
            item.addProperty("from", AddressCodec.format(from));
            Function caller = program.getFunctionManager().getFunctionContaining(from);
            if (caller != null) {
                item.addProperty("caller", caller.getName());
                item.addProperty("caller_address", AddressCodec.format(caller.getEntryPoint()));
            }
            item.addProperty("type", reference.getReferenceType().toString());
            item.addProperty("source", reference.getSource().toString());
            item.addProperty("operand", reference.getOperandIndex());
            evidence.add(item);
        }
        row.add("evidence", evidence);
        row.addProperty("evidence_omitted", calls.size() - evidence.size());
        return row;
    }
}
