package ghidracli;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.CancelledException;
import java.util.ArrayList;
import java.util.List;
import static ghidracli.JsonProtocol.errorResult;

/** Whole-body replacement; native annotation changes belong to the request transaction. */
final class FunctionBodyCommands {
    private final ProgramSession session;
    private final FunctionQueries functionQueries;

    FunctionBodyCommands(ProgramSession session, FunctionQueries functionQueries) {
        this.session = session;
        this.functionQueries = functionQueries;
    }

    JsonObject handleSet(JsonObject args) throws Exception {
        if (session.program() == null) return errorResult("No program loaded");
        String target = string(args, "target");
        Function function = functionQueries.findFunctionByNameOrAddress(target);
        if (function == null) return errorResult(functionQueries.buildFunctionTargetHint(target));
        if (function.isExternal()) {
            throw new IllegalArgumentException("External functions do not have editable bodies");
        }

        AddressSet requested = requestedBody(args, function);
        validateBody(requested, function);
        AddressSet before = new AddressSet(function.getBody());
        boolean changed = !before.hasSameAddresses(requested);
        JsonObject effects = emptyEffects();
        if (changed) {
            AddressSet removed = before.subtract(requested);
            List<Long> labels = removedLabels(function, removed);
            List<ReferenceState> references = removedReferences(function, removed);
            session.monitor().checkCancelled();
            // setBody acts on this function even when it is a thunk. Child namespaces,
            // including call-signature overrides, retain their native independent lifetime.
            function.setBody(requested);
            session.monitor().checkCancelled();
            if (!function.getBody().hasSameAddresses(requested)) {
                throw new IllegalStateException("Ghidra did not retain the requested function body");
            }
            effects = observedEffects(labels, references);
        }

        JsonObject result = new JsonObject();
        result.addProperty("function", function.getName());
        result.addProperty("address", AddressCodec.format(function.getEntryPoint()));
        result.addProperty("changed", changed);
        result.add("before", bodyToJson(before));
        result.add("after", bodyToJson(function.getBody()));
        result.add("effects", effects);
        return result;
    }

    private AddressSet requestedBody(JsonObject args, Function function) throws CancelledException {
        JsonElement value = args.get("ranges");
        if (value == null || !value.isJsonArray() || value.getAsJsonArray().isEmpty()) {
            throw new IllegalArgumentException("ranges must be a nonempty array of {start, end} objects");
        }
        AddressSet body = new AddressSet();
        for (JsonElement element : value.getAsJsonArray()) {
            session.monitor().checkCancelled();
            if (!element.isJsonObject()) {
                throw new IllegalArgumentException("Each body range must be a {start, end} object");
            }
            JsonObject range = element.getAsJsonObject();
            Address start = address(range, "start");
            Address end = address(range, "end");
            if (!start.getAddressSpace().equals(function.getEntryPoint().getAddressSpace())
                    || !end.getAddressSpace().equals(start.getAddressSpace())) {
                throw new IllegalArgumentException("Body ranges must use the function entry address space");
            }
            if (start.compareTo(end) > 0) {
                throw new IllegalArgumentException("Body range start must not exceed its inclusive end");
            }
            body.add(start, end);
        }
        return body;
    }

    private void validateBody(AddressSet body, Function function) throws CancelledException {
        if (!body.contains(function.getEntryPoint())) {
            throw new IllegalArgumentException("Function body must contain the existing entry point "
                + AddressCodec.format(function.getEntryPoint()));
        }
        if (body.getNumAddresses() > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("Function body exceeds Ghidra's maximum size of 0x7fffffff bytes");
        }
        AddressSet unmapped = body.subtract(session.program().getMemory());
        if (!unmapped.isEmpty()) {
            throw new IllegalArgumentException("Function body includes unmapped memory at "
                + AddressCodec.format(unmapped.getMinAddress()));
        }
        var listing = session.program().getListing();
        // Validate the union so overlapping or adjacent input ranges can jointly cover
        // a whole instruction without creating an artificial boundary between them.
        for (var range : body.getAddressRanges()) {
            session.monitor().checkCancelled();
            var first = listing.getInstructionContaining(range.getMinAddress());
            var last = listing.getInstructionContaining(range.getMaxAddress());
            if (first != null && !first.getMinAddress().equals(range.getMinAddress())) {
                throw new IllegalArgumentException("Body range starts inside instruction at "
                    + AddressCodec.format(first.getMinAddress()));
            }
            if (last != null && !last.getMaxAddress().equals(range.getMaxAddress())) {
                throw new IllegalArgumentException("Body range ends inside instruction at "
                    + AddressCodec.format(last.getMinAddress()));
            }
        }
        var overlapping = session.program().getFunctionManager().getFunctionsOverlapping(body);
        while (overlapping.hasNext()) {
            session.monitor().checkCancelled();
            Function other = overlapping.next();
            if (other.getID() != function.getID()) {
                throw new IllegalArgumentException("Function body overlaps function '" + other.getName()
                    + "' at " + AddressCodec.format(other.getEntryPoint()));
            }
        }
    }

    private List<Long> removedLabels(Function function, AddressSetView removed)
            throws CancelledException {
        List<Long> result = new ArrayList<>();
        var symbols = session.program().getSymbolTable().getSymbols(removed, SymbolType.LABEL, true);
        while (symbols.hasNext()) {
            session.monitor().checkCancelled();
            var symbol = symbols.next();
            if (symbol.getParentNamespace().getID() == function.getID()) result.add(symbol.getID());
        }
        return result;
    }

    private record ReferenceState(Address from, Address to, int operand, long variableSymbol) {}

    private List<ReferenceState> removedReferences(Function function, AddressSetView removed)
            throws CancelledException {
        List<ReferenceState> result = new ArrayList<>();
        var manager = session.program().getReferenceManager();
        var sources = manager.getReferenceSourceIterator(removed, true);
        while (sources.hasNext()) {
            session.monitor().checkCancelled();
            for (Reference reference : manager.getReferencesFrom(sources.next())) {
                var symbol = session.program().getSymbolTable().getSymbol(reference.getSymbolID());
                boolean ownVariable = symbol != null
                    && (symbol.getSymbolType() == SymbolType.PARAMETER
                        || symbol.getSymbolType() == SymbolType.LOCAL_VAR)
                    && symbol.getParentNamespace().getID() == function.getID();
                result.add(new ReferenceState(reference.getFromAddress(), reference.getToAddress(),
                    reference.getOperandIndex(), ownVariable ? symbol.getID() : -1));
            }
        }
        return result;
    }

    private JsonObject observedEffects(List<Long> labels, List<ReferenceState> references)
            throws CancelledException {
        long deletedLabels = 0;
        long deletedReferences = 0;
        long disassociated = 0;
        for (long id : labels) {
            session.monitor().checkCancelled();
            if (session.program().getSymbolTable().getSymbol(id) == null) ++deletedLabels;
        }
        for (ReferenceState before : references) {
            session.monitor().checkCancelled();
            Reference after = session.program().getReferenceManager()
                .getReference(before.from(), before.to(), before.operand());
            if (after == null) ++deletedReferences;
            else if (before.variableSymbol() >= 0 && after.getSymbolID() != before.variableSymbol()) {
                ++disassociated;
            }
        }
        JsonObject result = new JsonObject();
        result.addProperty("deleted_labels", deletedLabels);
        result.addProperty("deleted_references", deletedReferences);
        result.addProperty("disassociated_variable_references", disassociated);
        return result;
    }

    private static JsonObject emptyEffects() {
        JsonObject result = new JsonObject();
        result.addProperty("deleted_labels", 0);
        result.addProperty("deleted_references", 0);
        result.addProperty("disassociated_variable_references", 0);
        return result;
    }

    private JsonObject bodyToJson(AddressSetView body) throws CancelledException {
        JsonArray ranges = new JsonArray();
        for (var range : body.getAddressRanges()) {
            session.monitor().checkCancelled();
            JsonObject row = new JsonObject();
            row.addProperty("start", AddressCodec.format(range.getMinAddress()));
            row.addProperty("end", AddressCodec.format(range.getMaxAddress()));
            ranges.add(row);
        }
        JsonObject result = new JsonObject();
        result.add("body_ranges", ranges);
        result.addProperty("size", body.getNumAddresses());
        return result;
    }

    private Address address(JsonObject args, String key) {
        String input = string(args, key);
        Address address = AddressCodec.parse(session.program().getAddressFactory(), input);
        if (address == null) throw new IllegalArgumentException("Invalid " + key + " address: " + input);
        return address;
    }

    private static String string(JsonObject args, String key) {
        JsonElement value = args.get(key);
        if (value == null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString()
                || value.getAsString().isBlank()) {
            throw new IllegalArgumentException(key + " must be a nonempty string");
        }
        return value.getAsString();
    }
}
