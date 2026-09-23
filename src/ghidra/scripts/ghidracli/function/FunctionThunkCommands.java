package ghidracli.function;

import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;
import ghidracli.query.AddressCodec;
import ghidracli.session.ProgramSession;

import static ghidracli.protocol.JsonProtocol.errorResult;

/** Edits the selected function's direct thunk relation using native semantics. */
public final class FunctionThunkCommands {
    private final ProgramSession session;
    private final FunctionQueries functionQueries;

    public FunctionThunkCommands(ProgramSession session, FunctionQueries functionQueries) {
        this.session = session;
        this.functionQueries = functionQueries;
    }

    public JsonObject handleSet(JsonObject args) throws CancelledException {
        if (session.program() == null) return errorResult("No program loaded");
        Function function = resolveFunction(args, "target");
        Function destination = resolveFunction(args, "thunk_target");
        return edit(function, destination);
    }

    public JsonObject handleClear(JsonObject args) throws CancelledException {
        if (session.program() == null) return errorResult("No program loaded");
        return edit(resolveFunction(args, "target"), null);
    }

    private Function resolveFunction(JsonObject args, String key) throws CancelledException {
        session.monitor().checkCancelled();
        JsonElement value = args == null ? null : args.get(key);
        if (value == null || !value.isJsonPrimitive()
                || !value.getAsJsonPrimitive().isString() || value.getAsString().isBlank()) {
            throw new IllegalArgumentException(key + " must be a nonempty function name or address");
        }
        String target = value.getAsString();
        Function function = functionQueries.findFunctionByNameOrAddress(target);
        if (function == null) {
            throw new IllegalArgumentException(functionQueries.buildFunctionTargetHint(target));
        }
        return function;
    }

    private JsonObject edit(Function function, Function destination) throws CancelledException {
        if (function.isExternal()) {
            throw new IllegalArgumentException("External functions cannot have a thunk relation");
        }
        JsonObject before = snapshot(function);
        boolean changed = !sameFunction(function.getThunkedFunction(false), destination);
        session.monitor().checkCancelled();
        if (changed) {
            // Native validation rejects self/cycles. Edit this direct relation, never
            // the final signature owner; clearing exposes this function's saved definition.
            function.setThunkedFunction(destination);
        }
        session.monitor().checkCancelled();
        if (!sameFunction(function.getThunkedFunction(false), destination)) {
            throw new IllegalStateException("Ghidra did not retain the requested thunk relation");
        }

        JsonObject result = new JsonObject();
        result.addProperty("status", changed ? "updated" : "unchanged");
        result.addProperty("function", function.getName());
        result.addProperty("address", AddressCodec.format(function.getEntryPoint()));
        result.add("before", before);
        result.add("after", snapshot(function));
        return result;
    }

    private JsonObject snapshot(Function function) throws CancelledException {
        session.monitor().checkCancelled();
        JsonObject result = new JsonObject();
        result.addProperty("name", function.getName());
        result.addProperty("address", AddressCodec.format(function.getEntryPoint()));
        result.addProperty("namespace", function.getParentNamespace().getName(true));
        result.addProperty("is_thunk", function.isThunk());
        result.addProperty("signature", function.getPrototypeString(false, false));
        result.addProperty("calling_convention", function.getCallingConventionName());
        result.addProperty("no_return", function.hasNoReturn());
        result.add("stack_purge", functionQueries.stackPurgeToJson(function));
        // Query the selected function so native thunk-specific THIS types survive.
        JsonObject signature = functionQueries.signatureDetailsToJson(function);
        if (!function.isThunk()) {
            signature.add("thunk_function", JsonNull.INSTANCE);
            signature.add("thunk_address", JsonNull.INSTANCE);
            signature.addProperty("effective_function", function.getName());
            signature.addProperty("effective_address", AddressCodec.format(function.getEntryPoint()));
        }
        result.add("signature_details", signature);
        return result;
    }

    private static boolean sameFunction(Function left, Function right) {
        return left == null ? right == null : right != null && left.getID() == right.getID();
    }
}
