package ghidracli.analysis;

import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import ghidra.app.decompiler.util.FillOutStructureHelper;
import ghidra.app.decompiler.util.FillOutStructureHelper.OffsetPcodeOpPair;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.exception.CancelledException;
import ghidracli.function.FunctionQueries;
import ghidracli.function.FunctionVariables;
import ghidracli.protocol.JsonProtocol;
import ghidracli.query.AddressCodec;
import ghidracli.session.ProgramSession;
import ghidracli.types.StructureFields;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.IdentityHashMap;
import java.util.Set;

import static ghidracli.protocol.JsonProtocol.errorResult;
import static ghidracli.protocol.JsonProtocol.getArgBool;
import static ghidracli.protocol.JsonProtocol.getNonnegativeIntArg;

/** Read-only exposure of Ghidra's structure recovery for one whole variable. */
public final class StructureInferenceCommands {
    private final ProgramSession session;
    private final FunctionVariables variables;

    public StructureInferenceCommands(ProgramSession session, FunctionQueries functionQueries) {
        this.session = session;
        this.variables = new FunctionVariables(session, functionQueries);
    }

    public JsonObject handleInfer(JsonObject args) throws CancelledException {
        try {
            boolean withAccesses = getArgBool(args, "with_accesses", false);
            int maxAccesses = getNonnegativeIntArg(args, "max_accesses", 1000);
            if (maxAccesses == 0) throw new IllegalArgumentException("max_accesses must be positive");
            if (!withAccesses && args.has("max_accesses") && !args.get("max_accesses").isJsonNull()) {
                throw new IllegalArgumentException("max_accesses requires with_accesses");
            }
            Function function = variables.function(args);
            String name = FunctionVariables.variableName(args);
            long modification = session.program().getModificationNumber();
            FunctionVariables.Decompilation decompiled = variables.decompile(function, args);
            FunctionVariables.Selection selected = variables.select(function, decompiled.symbols(), name, args);
            if (selected.error() != null) return selected.error();
            HighVariable root = wholeVariable(decompiled.high(), selected.symbol());
            // Match the GUI's eligibility without requiring a pointer type first.
            if (root.getDataType() == null || root.getDataType().getLength() > session.program().getDefaultPointerSize()) {
                throw new IllegalArgumentException("Structure inference requires a variable no larger than the program pointer size");
            }

            session.monitor().checkCancelled();
            FillOutStructureHelper helper = new FillOutStructureHelper(session.program(), session.monitor());
            // Detached candidate; preserve existing structures and namespaces, and stay in this function.
            Structure structure = helper.processStructure(root, function, true, false, null);
            // Native recovery does not poll the monitor throughout its intrafunction traversal.
            session.monitor().checkCancelled();
            if (structure == null && helper.getComponentMap().getSize() != 0) {
                throw new IllegalStateException("Ghidra could not represent the inferred structure size: "
                    + helper.getComponentMap().getSize());
            }

            JsonObject result = FunctionVariables.context(function);
            result.add("variable", FunctionVariables.describe(selected.symbol()));
            result.add("structure", structure == null ? JsonNull.INSTANCE : describe(structure));
            result.add("warnings", DecompileWarnings.collect(decompiled.results()));
            if (withAccesses) addAccesses(result, helper, maxAccesses);
            session.monitor().checkCancelled();
            if (session.program().getModificationNumber() != modification) {
                // A supported Ghidra version must not turn this read into a saved mutation.
                throw new IllegalStateException("Structure inference unexpectedly modified the program");
            }
            return result;
        } catch (CancelledException e) {
            throw e;
        } catch (Exception e) {
            return errorResult("Failed to infer structure: " + e.getMessage(), e);
        }
    }

    private HighVariable wholeVariable(HighFunction high, HighSymbol symbol) throws CancelledException {
        Set<HighVariable> roots = Collections.newSetFromMap(new IdentityHashMap<>());
        var nodes = high.locRange();
        while (nodes.hasNext()) {
            session.monitor().checkCancelled();
            HighVariable variable = nodes.next().getHigh();
            if (variable != null && variable.getSymbol() == symbol) roots.add(variable);
        }
        if (symbol.getHighVariable() != null) roots.add(symbol.getHighVariable());
        if (roots.size() == 1) {
            HighVariable root = roots.iterator().next();
            if (root.getSize() == symbol.getSize() && root.getOffset() <= 0) return root;
        }
        JsonObject detail = new JsonObject();
        detail.add("variable", FunctionVariables.describe(symbol));
        detail.addProperty("high_variable_count", roots.size());
        throw new JsonProtocol.CommandException(
            "Variable does not resolve to one whole HighVariable; inspect the function's High P-code", detail);
    }

    private JsonObject describe(Structure structure) throws CancelledException {
        JsonObject result = new JsonObject();
        result.addProperty("kind", "struct");
        result.addProperty("size", structure.isZeroLength() ? 0 : structure.getLength());
        result.addProperty("packing_enabled", structure.isPackingEnabled());
        JsonArray components = new JsonArray();
        for (var component : structure.getDefinedComponents()) {
            session.monitor().checkCancelled();
            components.add(StructureFields.describe(component));
        }
        result.add("components", components);
        return result;
    }

    private void addAccesses(JsonObject result, FillOutStructureHelper helper, int limit)
            throws CancelledException {
        var accesses = new ArrayList<OffsetPcodeOpPair>(helper.getLoadPcodeOps());
        accesses.addAll(helper.getStorePcodeOps());
        accesses.sort(Comparator.comparing(OffsetPcodeOpPair::getOffset)
            .thenComparing(pair -> pair.getPcodeOp().getSeqnum().getTarget())
            .thenComparingInt(pair -> pair.getPcodeOp().getSeqnum().getTime()));
        JsonArray rows = new JsonArray();
        for (OffsetPcodeOpPair pair : accesses) {
            session.monitor().checkCancelled();
            if (rows.size() == limit) break;
            PcodeOp op = pair.getPcodeOp();
            JsonObject row = new JsonObject();
            row.addProperty("offset", pair.getOffset());
            row.addProperty("size", op.getOpcode() == PcodeOp.LOAD
                ? op.getOutput().getSize() : op.getInput(2).getSize());
            row.addProperty("mnemonic", op.getMnemonic());
            row.addProperty("instruction_address", AddressCodec.format(op.getSeqnum().getTarget()));
            row.addProperty("sequence", op.getSeqnum().getTime());
            rows.add(row);
        }
        result.add("accesses", rows);
        JsonObject status = new JsonObject();
        status.addProperty("returned", rows.size());
        status.addProperty("total", accesses.size());
        status.addProperty("max_accesses", limit);
        status.addProperty("truncated", rows.size() < accesses.size());
        result.add("accesses_status", status);
    }
}
