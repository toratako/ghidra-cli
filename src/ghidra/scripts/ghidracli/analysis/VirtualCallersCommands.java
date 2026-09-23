package ghidracli.analysis;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;
import ghidracli.function.FunctionQueries;
import ghidracli.query.AddressCodec;
import ghidracli.query.AddressResolver;
import ghidracli.session.ProgramSession;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import static ghidracli.protocol.JsonProtocol.errorResult;

/** Read-only, request-local virtual-call candidates for a caller-selected table. */
public final class VirtualCallersCommands {
    private final ProgramSession session;
    private final FunctionQueries functions;
    private final VtableReader tables;

    public VirtualCallersCommands(ProgramSession session, AddressResolver addresses,
            FunctionQueries functions) {
        this.session = session;
        this.functions = functions;
        tables = new VtableReader(session, addresses);
    }

    public JsonObject handle(JsonObject args) throws Exception {
        if (session.program() == null) return errorResult("No program loaded");
        session.monitor().checkCancelled();
        String selector = required(args, "function");
        Function target = functions.findFunctionByNameOrAddress(selector);
        if (target == null) throw new IllegalArgumentException(functions.buildFunctionTargetHint(selector));

        JsonObject tableArgs = new JsonObject();
        tableArgs.addProperty("target", required(args, "vtable"));
        tableArgs.addProperty("abi", required(args, "abi"));
        tableArgs.add("entries", args.get("entries"));
        JsonObject table = tables.read(tableArgs);
        Address addressPoint = AddressCodec.parse(session.program().getAddressFactory(),
            table.get("address").getAsString());
        JsonArray slots = new JsonArray();
        JsonArray unreadable = new JsonArray();
        Map<Long, JsonObject> offsets = new LinkedHashMap<>();
        for (JsonElement element : table.getAsJsonArray("entries")) {
            session.monitor().checkCancelled();
            JsonObject entry = element.getAsJsonObject();
            if (!entry.get("readable").getAsBoolean()) {
                JsonObject failure = new JsonObject();
                failure.addProperty("reason", "unreadable_vtable_entry");
                failure.add("slot_address", entry.get("address"));
                failure.add("slot_offset", entry.get("offset"));
                unreadable.add(failure);
                continue;
            }
            if (entry.get("is_null").getAsBoolean()) continue;
            String match = matches(entry, target);
            if (match == null) continue;
            JsonObject slot = entry.deepCopy();
            slot.addProperty("match", match);
            slots.add(slot);
            offsets.put(slot.get("offset").getAsLong(), slot);
        }

        // Resolve scope and validate budgets even if no selected slot reaches the target.
        DecompileScan search = new DecompileScan(session, functions, args, "within");
        if (!offsets.isEmpty()) {
            search.run((function, results) -> {
                VirtualCallTrace.Findings found = VirtualCallTrace.find(
                    session, function, results, addressPoint, offsets.keySet());
                for (JsonElement element : found.calls()) {
                    session.monitor().checkCancelled();
                    JsonObject call = element.getAsJsonObject();
                    JsonObject slot = offsets.get(call.get("slot_offset").getAsLong());
                    call.add("slot_index", slot.get("index"));
                    call.add("slot_address", slot.get("address"));
                }
                return new DecompileScan.Findings(found.calls(), found.unresolved());
            });
        }
        JsonObject scan = search.scan("omitted_calls");
        boolean tableComplete = table.get("complete").getAsBoolean();
        scan.addProperty("table_complete", tableComplete);
        if (offsets.isEmpty()) {
            // No decompilation is needed to establish an empty result for these slots.
            // Unvisited functions are still counted; this is not a limit-induced gap.
            scan.addProperty("complete", tableComplete);
            scan.addProperty("stop_reason", tableComplete ? "target_not_in_table" : "table_read_failed");
        } else if (!tableComplete) {
            scan.addProperty("complete", false);
            if (scan.get("stop_reason").isJsonNull()) scan.addProperty("stop_reason", "table_read_failed");
        }
        JsonArray unresolved = search.unresolved();
        unresolved.addAll(unreadable);
        scan.add("unresolved", unresolved);
        JsonObject identity = new JsonObject();
        identity.addProperty("function", target.getName(true));
        identity.addProperty("address", AddressCodec.format(target.getEntryPoint()));
        JsonObject result = new JsonObject();
        result.add("target", identity);
        result.add("vtable", table);
        result.add("slots", slots);
        result.add("scope", search.scope());
        result.add("scan", scan);
        result.add("calls", search.rows());
        session.monitor().checkCancelled();
        return result;
    }

    private String matches(JsonObject entry, Function target) throws CancelledException {
        JsonElement code = entry.get("code_address");
        if (code == null || code.isJsonNull()) return null;
        Address address = AddressCodec.parse(session.program().getAddressFactory(), code.getAsString());
        Function function = session.program().getFunctionManager().getFunctionAt(address);
        Set<Address> visited = new HashSet<>();
        boolean direct = true;
        while (function != null && visited.add(function.getEntryPoint())) {
            session.monitor().checkCancelled();
            if (function.getEntryPoint().equals(target.getEntryPoint())) return direct ? "direct" : "thunk";
            if (!function.isThunk()) break;
            function = function.getThunkedFunction(false);
            direct = false;
        }
        return null;
    }

    private static String required(JsonObject args, String name) {
        JsonElement value = args == null ? null : args.get(name);
        if (value == null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString()
                || value.getAsString().isBlank()) {
            throw new IllegalArgumentException(name + " must be a non-empty string");
        }
        return value.getAsString();
    }
}
