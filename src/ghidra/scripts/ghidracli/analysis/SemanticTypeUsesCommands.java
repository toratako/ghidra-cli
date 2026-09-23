package ghidracli.analysis;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.EquateSymbol;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.UnionFacetSymbol;
import ghidra.util.exception.CancelledException;
import ghidracli.function.FunctionQueries;
import ghidracli.query.AddressCodec;
import ghidracli.session.ProgramSession;
import ghidracli.types.StructureFields;
import ghidracli.types.TypeFieldTarget;
import ghidracli.types.TypeResolver;
import ghidracli.types.TypeUseMatcher;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Set;

import static ghidracli.protocol.JsonProtocol.errorResult;
import static ghidracli.protocol.JsonProtocol.getArgString;

/** Fresh semantic searches, serialized on ProgramSession's original program thread. */
public final class SemanticTypeUsesCommands {
    private final ProgramSession session;
    private final TypeResolver resolver;
    private final FunctionQueries functionQueries;

    public SemanticTypeUsesCommands(ProgramSession session, TypeResolver resolver,
            FunctionQueries functionQueries) {
        this.session = session;
        this.resolver = resolver;
        this.functionQueries = functionQueries;
    }

    public JsonObject handleVariables(JsonObject args) throws Exception {
        if (session.program() == null) return errorResult("No program loaded");
        String kind = getArgString(args, "kind");
        if (kind != null && !kind.equals("variable")) {
            throw new IllegalArgumentException("Semantic variable search requires kind variable");
        }
        DataType target = target(args);
        DecompileScan search = new DecompileScan(session, functionQueries, args, "function");
        TypeUseMatcher matcher = new TypeUseMatcher(session, target);
        search.run((function, results) ->
            new DecompileScan.Findings(variables(function, results, matcher), new JsonArray()));
        JsonObject result = result(target, search);
        JsonArray kinds = new JsonArray();
        kinds.add("variable");
        result.add("kinds", kinds);
        return result;
    }

    public JsonObject handleFields(JsonObject args) throws Exception {
        if (session.program() == null) return errorResult("No program loaded");
        DataType target = target(args);
        DataTypeComponent field = TypeFieldTarget.resolve(target, args);
        DecompileScan search = new DecompileScan(session, functionQueries, args, "function");
        search.run((function, results) -> {
            FieldUses.Findings findings = FieldUses.find(session, function, results, field);
            return new DecompileScan.Findings(findings.uses(), findings.unresolved());
        });
        JsonObject result = result(target, search);
        result.add("target_field", StructureFields.describe(field));
        JsonObject scan = result.getAsJsonObject("scan");
        scan.add("unresolved", search.unresolved());
        return result;
    }

    private DataType target(JsonObject args) throws CancelledException {
        String name = getArgString(args, "type_name");
        if (name == null || name.isBlank()) throw new IllegalArgumentException("Type name required");
        session.monitor().checkCancelled();
        DataType target = resolver.resolveRegisteredDataType(name);
        if (target == null) throw new IllegalArgumentException("Registered type not found: " + name);
        return target;
    }

    private JsonArray variables(Function function, DecompileResults results, TypeUseMatcher matcher)
            throws CancelledException {
        JsonArray rows = new JsonArray();
        Set<HighSymbol> visited = Collections.newSetFromMap(new IdentityHashMap<>());
        var symbols = results.getHighFunction().getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            session.monitor().checkCancelled();
            HighSymbol symbol = symbols.next();
            // The local map also includes constants and union-field annotations.
            if (!visited.add(symbol) || symbol.isGlobal() || symbol instanceof EquateSymbol
                    || symbol instanceof UnionFacetSymbol) continue;
            JsonObject row = matcher.match(symbol.getDataType());
            if (row == null) continue;
            row.addProperty("kind", "variable");
            row.addProperty("role", symbol.isParameter() ? "parameter" : "local");
            row.addProperty("function", function.getName(true));
            row.addProperty("address", AddressCodec.format(function.getEntryPoint()));
            row.addProperty("name", symbol.getName());
            row.addProperty("storage", symbol.getStorage().toString());
            if (symbol.isParameter()) {
                row.addProperty("ordinal", symbol.getCategoryIndex());
            } else {
                row.addProperty("first_use", symbol.getPCAddress() == null
                    ? null : AddressCodec.format(symbol.getPCAddress()));
            }
            row.addProperty("evidence", "decompiler");
            rows.add(row);
        }
        return rows;
    }

    private static JsonObject result(DataType target, DecompileScan search) {
        JsonObject result = new JsonObject();
        result.addProperty("target_type_path", target.getPathName());
        result.add("scope", search.scope());
        result.add("scan", search.scan("omitted_uses"));
        result.add("uses", search.rows());
        return result;
    }
}
