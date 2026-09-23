package ghidracli.types;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.CancelledException;
import ghidracli.query.AddressCodec;
import ghidracli.query.ListQuery;
import ghidracli.session.ProgramSession;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Set;

import static ghidracli.protocol.JsonProtocol.errorResult;
import static ghidracli.protocol.JsonProtocol.getArgString;

/** Declaration uses from the database; no decompilation or type registration. */
public final class TypeUsesCommands {
    private final ProgramSession session;
    private final TypeResolver resolver;

    public TypeUsesCommands(ProgramSession session, TypeResolver resolver) {
        this.session = session;
        this.resolver = resolver;
    }

    public JsonObject handleUses(JsonObject args) throws CancelledException {
        if (session.program() == null) return errorResult("No program loaded");
        String name = getArgString(args, "type_name");
        if (name == null || name.isBlank()) throw new IllegalArgumentException("Type name required");
        String kind = getArgString(args, "kind");
        if (kind != null && !kind.equals("data") && !kind.equals("signature")) {
            throw new IllegalArgumentException("kind must be data or signature");
        }
        long limit = ListQuery.pageArgument(args, "limit");
        session.monitor().checkCancelled();
        DataType target = resolver.resolveRegisteredDataType(name);
        if (target == null) return errorResult("Registered type not found: " + name);
        Scan scan = new Scan(target, limit);
        JsonArray kinds = new JsonArray();
        if (kind == null || kind.equals("data")) kinds.add("data");
        if (kind == null || kind.equals("signature")) kinds.add("signature");

        boolean complete = true;
        if (kind == null || kind.equals("data")) complete = scanData(scan);
        if (complete && (kind == null || kind.equals("signature"))) {
            complete = scanFunctions(scan);
        }
        session.monitor().checkCancelled();
        JsonObject progress = new JsonObject();
        progress.addProperty("complete", complete);
        progress.addProperty("stop_reason", complete ? null : "limit");
        JsonObject result = new JsonObject();
        result.addProperty("target_type_path", target.getPathName());
        result.add("kinds", kinds);
        result.add("scan", progress);
        result.add("uses", scan.rows);
        return result;
    }

    private boolean scanData(Scan scan) throws CancelledException {
        var iterator = session.program().getListing().getDefinedData(true);
        while (iterator.hasNext()) {
            session.monitor().checkCancelled();
            if (scan.full()) return false;
            var data = iterator.next();
            JsonObject row = scan.match(data.getDataType());
            if (row == null) continue;
            row.addProperty("kind", "data");
            row.addProperty("address", AddressCodec.format(data.getAddress()));
            var symbol = data.getPrimarySymbol();
            row.addProperty("name", symbol == null ? null : symbol.getName(true));
            scan.rows.add(row);
        }
        return true;
    }

    private boolean scanFunctions(Scan scan) throws CancelledException {
        // FunctionManager.getFunctions(boolean) restricts its iterator to mapped
        // memory. A null symbol address set includes unmapped and external functions.
        var iterator = session.program().getSymbolTable().getSymbols(null, SymbolType.FUNCTION, true);
        var functions = session.program().getFunctionManager();
        while (iterator.hasNext()) {
            session.monitor().checkCancelled();
            if (scan.full()) return false;
            Function function = functions.getFunction(iterator.next().getID());
            addSignature(scan, function, function.getReturn(), "return");
            for (Parameter parameter : function.getParameters()) {
                session.monitor().checkCancelled();
                if (scan.full()) return false;
                addSignature(scan, function, parameter, "parameter");
            }
        }
        return true;
    }

    private void addSignature(Scan scan, Function function, Parameter parameter, String role)
            throws CancelledException {
        // Use the declared type, before ABI-forced indirection, for the match.
        JsonObject row = scan.match(parameter.getFormalDataType());
        if (row == null) return;
        row.addProperty("kind", "signature");
        row.addProperty("role", role);
        row.addProperty("address", AddressCodec.format(function.getEntryPoint()));
        row.addProperty("function", function.getName(true));
        row.addProperty("name", parameter.getName());
        if (role.equals("parameter")) row.addProperty("ordinal", parameter.getOrdinal());
        row.addProperty("signature_source", function.getSignatureSource().name());
        row.addProperty("auto_parameter", parameter.getAutoParameterType() == null
            ? null : parameter.getAutoParameterType().name());
        row.addProperty("forced_indirect", parameter.isForcedIndirect());
        if (parameter.isForcedIndirect()) {
            row.addProperty("effective_type", parameter.getDataType().getDisplayName());
            row.addProperty("effective_type_path", parameter.getDataType().getPathName());
        }
        row.addProperty("is_external", function.isExternal());
        row.addProperty("is_thunk", function.isThunk());
        if (function.isThunk()) {
            Function immediate = function.getThunkedFunction(false);
            Function effective = function.getThunkedFunction(true);
            row.addProperty("thunk_function", immediate.getName(true));
            row.addProperty("thunk_address", AddressCodec.format(immediate.getEntryPoint()));
            row.addProperty("effective_function", effective.getName(true));
            row.addProperty("effective_address", AddressCodec.format(effective.getEntryPoint()));
        }
        scan.rows.add(row);
    }

    /** Request-local state; no Program or datatype survives the request. */
    private final class Scan {
        final JsonArray rows = new JsonArray();
        final DataTypeManager manager;
        final long targetId;
        final long limit;

        Scan(DataType target, long limit) {
            manager = session.program().getDataTypeManager();
            targetId = manager.getID(target);
            this.limit = limit;
        }

        boolean full() {
            return limit > 0 && rows.size() >= limit;
        }

        JsonObject match(DataType declared) throws CancelledException {
            JsonArray wrappers = new JsonArray();
            Set<DataType> visited = Collections.newSetFromMap(new IdentityHashMap<>());
            DataType current = declared;
            while (current != null && visited.add(current)) {
                session.monitor().checkCancelled();
                // getID alone does not check the owning manager. Pointer/array
                // types have no universal ID; structural equivalence merges distinct types.
                if (current.getDataTypeManager() == manager && manager.contains(current)
                        && manager.getID(current) == targetId) {
                    JsonObject row = new JsonObject();
                    row.addProperty("type", declared.getDisplayName());
                    row.addProperty("type_path", declared.getPathName());
                    row.add("wrappers", wrappers);
                    return row;
                }
                JsonObject wrapper = new JsonObject();
                wrapper.addProperty("type_path", current.getPathName());
                if (current instanceof TypeDef alias) {
                    wrapper.addProperty("kind", "typedef");
                    current = alias.getDataType();
                } else if (current instanceof Pointer pointer) {
                    wrapper.addProperty("kind", "pointer");
                    wrapper.addProperty("size", pointer.getLength());
                    current = pointer.getDataType();
                } else if (current instanceof Array array) {
                    wrapper.addProperty("kind", "array");
                    wrapper.addProperty("count", array.getNumElements());
                    current = array.getDataType();
                } else {
                    break;
                }
                wrappers.add(wrapper);
            }
            return null;
        }
    }
}
