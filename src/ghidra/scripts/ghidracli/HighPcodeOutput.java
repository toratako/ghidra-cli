package ghidracli;

import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.EquateSymbol;
import ghidra.program.model.pcode.HighConstant;
import ghidra.program.model.pcode.HighGlobal;
import ghidra.program.model.pcode.HighLocal;
import ghidra.program.model.pcode.HighParam;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.exception.CancelledException;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Set;

/** Bounded projection of a complete request-local High IR index. */
final class HighPcodeOutput {
    private final ProgramSession session;
    private final HighPcodeModel model;
    private final AnalysisLimits limits;
    private final Set<HighPcodeModel.Node> selected =
        Collections.newSetFromMap(new IdentityHashMap<>());
    private final Set<HighPcodeModel.Edge> selectedEdges =
        Collections.newSetFromMap(new IdentityHashMap<>());
    private boolean nodeLimited;
    private boolean edgeLimited;
    private long returnedRelationships;

    HighPcodeOutput(ProgramSession session, HighPcodeModel model, AnalysisLimits limits) {
        this.session = session;
        this.model = model;
        this.limits = limits;
    }

    JsonObject render(Function function, JsonArray warnings) throws CancelledException {
        select();
        JsonObject result = AnalysisContext.create(session, function, "high_pcode");
        result.addProperty("level", "high");
        result.add("limits", limits.toJson("operations_values_blocks_high_variables_symbols", "relationships"));
        result.add("warnings", warnings);
        JsonArray operations = new JsonArray();
        JsonArray values = new JsonArray();
        JsonArray blocks = new JsonArray();
        JsonArray variables = new JsonArray();
        JsonArray symbols = new JsonArray();
        JsonArray edges = new JsonArray();
        for (HighPcodeModel.Node node : model.order) {
            session.monitor().checkCancelled();
            if (!selected.contains(node)) continue;
            if (node instanceof HighPcodeModel.Operation op) operations.add(operation(op));
            else if (node instanceof HighPcodeModel.Value value) values.add(value(value));
            else if (node instanceof HighPcodeModel.Block block) blocks.add(block(block));
            else if (node instanceof HighPcodeModel.Variable variable) variables.add(variable(variable));
            else if (node instanceof HighPcodeModel.Symbol symbol) symbols.add(symbol(symbol));
        }
        for (HighPcodeModel.Edge edge : model.edges) {
            session.monitor().checkCancelled();
            if (!selectedEdges.contains(edge)) continue;
            JsonObject json = new JsonObject();
            json.addProperty("id", edge.id);
            json.add("source", ref(edge.source, "unresolved"));
            json.add("target", ref(edge.target, "unresolved"));
            json.addProperty("source_out_index", edge.sourceOutIndex);
            json.addProperty("target_in_index", edge.targetInIndex);
            edges.add(json);
        }
        result.add("operations", operations);
        result.add("values", values);
        result.add("blocks", blocks);
        result.add("edges", edges);
        result.add("high_variables", variables);
        result.add("symbols", symbols);
        JsonObject completion = new JsonObject();
        JsonObject scan = new JsonObject();
        scan.addProperty("complete", true);
        scan.addProperty("nodes", model.order.size());
        scan.addProperty("edges", model.relationshipCount);
        completion.add("scan", scan);
        JsonObject output = new JsonObject();
        output.addProperty("complete", !nodeLimited && !edgeLimited);
        output.addProperty("nodes", selected.size());
        output.addProperty("edges", returnedRelationships);
        JsonArray reasons = new JsonArray();
        if (nodeLimited) reasons.add("max_nodes");
        if (edgeLimited) reasons.add("max_edges");
        output.add("reasons", reasons);
        completion.add("output", output);
        JsonObject collections = new JsonObject();
        collections.add("operations", counts(operations.size(), model.operations.size()));
        collections.add("values", counts(values.size(), model.values.size()));
        collections.add("blocks", counts(blocks.size(), model.blocks.size()));
        collections.add("high_variables", counts(variables.size(), model.variables.size()));
        collections.add("symbols", counts(symbols.size(), model.symbols.size()));
        collections.add("control_flow_edges", counts(edges.size(), model.edges.size()));
        completion.add("collections", collections);
        result.add("completion", completion);
        return result;
    }

    private void select() throws CancelledException {
        for (HighPcodeModel.Node node : model.order) {
            session.monitor().checkCancelled();
            if (selected.size() >= limits.maxNodes()) {
                nodeLimited = true;
                continue;
            }
            long cost = node.relationshipCount();
            // Definition/output is one logical link whichever endpoint is admitted
            // first. A value can expose its known definition even if that operation
            // is omitted; that reference must still consume the edge budget.
            if (node instanceof HighPcodeModel.Value value) {
                HighPcodeModel.Operation definition = model.operationIndex.get(value.source.getDef());
                if (definition != null && !selected.contains(definition)) cost++;
            } else if (node instanceof HighPcodeModel.Operation operation) {
                HighPcodeModel.Value output = model.valueIndex.get(operation.source.getOutput());
                if (output != null && selected.contains(output)) cost--;
            }
            // All operation slots and its output/block links are admitted together.
            // A single enormous call or phi cannot evade the edge cap via its inputs.
            if (cost > limits.maxEdges() - returnedRelationships) {
                edgeLimited = true;
                continue;
            }
            selected.add(node);
            returnedRelationships += cost;
        }
        for (HighPcodeModel.Edge edge : model.edges) {
            session.monitor().checkCancelled();
            if (returnedRelationships >= limits.maxEdges()) {
                edgeLimited = true;
                break;
            }
            selectedEdges.add(edge);
            returnedRelationships++;
        }
    }

    private JsonObject operation(HighPcodeModel.Operation indexed) throws CancelledException {
        PcodeOp op = indexed.source;
        JsonObject json = node(indexed);
        json.addProperty("mnemonic", op.getMnemonic());
        json.addProperty("opcode", op.getOpcode());
        json.addProperty("instruction_address", AddressCodec.format(op.getSeqnum().getTarget()));
        json.addProperty("sequence", op.getSeqnum().getTime());
        json.add("block", ref(indexed.block, "none"));
        json.addProperty("block_order", indexed.blockOrder);
        json.add("output", ref(model.valueIndex.get(op.getOutput()), "none"));
        JsonArray inputs = new JsonArray();
        for (int slot = 0; slot < op.getNumInputs(); slot++) {
            session.monitor().checkCancelled();
            Varnode input = op.getInput(slot);
            JsonObject operand = new JsonObject();
            operand.addProperty("slot", slot);
            operand.addProperty("role", HighPcodeModel.inputRole(op, slot));
            if (HighPcodeModel.isOperationReference(op, slot)) {
                operand.addProperty("kind", "operation");
                PcodeOp target = input == null ? null : model.source.getOpRef((int) input.getOffset());
                operand.add("operation", ref(model.operationIndex.get(target), "unresolved"));
                operand.add("encoding", input == null ? JsonNull.INSTANCE : storage(input));
            } else if (HighPcodeModel.isSpaceReference(op, slot)) {
                operand.addProperty("kind", "address_space");
                AddressSpace space = input == null ? null : session.program().getAddressFactory()
                    .getAddressSpace((int) input.getOffset());
                operand.addProperty("space", space == null ? null : space.getName());
                operand.addProperty("state", space == null ? "unresolved" : "resolved");
                operand.add("encoding", input == null ? JsonNull.INSTANCE : storage(input));
            } else {
                operand.addProperty("kind", "value");
                operand.add("value", ref(model.valueIndex.get(input), "unresolved"));
            }
            if (op.getOpcode() == PcodeOp.MULTIEQUAL) {
                HighPcodeModel.Edge predecessor = null;
                if (indexed.block != null) {
                    for (HighPcodeModel.Edge edge : indexed.block.incoming) {
                        if (edge.targetInIndex == slot) { predecessor = edge; break; }
                    }
                }
                operand.add("incoming_edge", edgeRef(predecessor));
            }
            inputs.add(operand);
        }
        json.add("inputs", inputs);
        return json;
    }

    private JsonObject value(HighPcodeModel.Value value) throws CancelledException {
        Varnode source = value.source;
        JsonObject json = storage(source);
        json.addProperty("id", value.id);
        PcodeOp definition = source.getDef();
        json.add("definition", ref(model.operationIndex.get(definition), definition == null ? "none" : "unresolved"));
        json.addProperty("origin", definition != null ? "defined" : source.isConstant() ? "constant"
            : source.isInput() ? "input" : source.isUnaffected() ? "unaffected" : "no_definition");
        json.addProperty("is_input", source.isInput());
        json.addProperty("is_persistent", source.isPersistent());
        json.addProperty("is_address_tied", source.isAddrTied());
        json.addProperty("is_unaffected", source.isUnaffected());
        json.add("high_variable", ref(value.variable, "none"));
        JsonArray uses = new JsonArray();
        for (HighPcodeModel.Use use : value.uses) {
            session.monitor().checkCancelled();
            if (!selected.contains(use.operation)) continue;
            JsonObject entry = new JsonObject();
            entry.addProperty("operation", use.operation.id);
            entry.addProperty("slot", use.slot);
            entry.addProperty("role", HighPcodeModel.inputRole(use.operation.source, use.slot));
            uses.add(entry);
        }
        json.add("uses", uses);
        json.add("uses_status", counts(uses.size(), value.uses.size()));
        return json;
    }

    private JsonObject block(HighPcodeModel.Block block) throws CancelledException {
        JsonObject json = node(block);
        json.addProperty("native_index", block.source.getIndex());
        address(json, "start", block.source.getStart());
        address(json, "stop", block.source.getStop());
        JsonArray operations = selectedIds(block.operations);
        json.add("operations", operations);
        json.add("operations_status", counts(operations.size(), block.operations.size()));
        JsonArray incoming = selectedEdgeIds(block.incoming);
        json.add("incoming_edges", incoming);
        json.add("incoming_edges_status", counts(incoming.size(), block.source.getInSize()));
        JsonArray outgoing = selectedEdgeIds(block.outgoing);
        json.add("outgoing_edges", outgoing);
        json.add("outgoing_edges_status", counts(outgoing.size(), block.source.getOutSize()));
        return json;
    }

    private JsonObject variable(HighPcodeModel.Variable variable) throws CancelledException {
        HighVariable source = variable.source;
        JsonObject json = node(variable);
        json.addProperty("name", source.getName());
        dataType(json, source.getDataType());
        json.addProperty("size", source.getSize());
        json.addProperty("kind", source instanceof HighParam ? "parameter" : source instanceof HighLocal ? "local"
            : source instanceof HighGlobal ? "global" : source instanceof HighConstant ? "constant" : "other");
        if (source instanceof HighParam parameter) json.addProperty("parameter_index", parameter.getSlot());
        json.add("symbol", ref(variable.symbol, "none"));
        json.addProperty("symbol_offset", source.getOffset() < 0 ? null : source.getOffset());
        json.add("representative", ref(variable.representative, "none"));
        JsonArray values = selectedIds(variable.instances);
        json.add("values", values);
        json.add("values_status", counts(values.size(), variable.instances.size()));
        return json;
    }

    private JsonObject symbol(HighPcodeModel.Symbol symbol) throws CancelledException {
        var source = symbol.source;
        JsonObject json = node(symbol);
        json.addProperty("name", source.getName());
        dataType(json, source.getDataType());
        json.addProperty("size", source.getSize());
        json.addProperty("kind", source instanceof EquateSymbol ? "equate"
            : source.isParameter() ? "parameter" : source.isGlobal() ? "global" : "local");
        if (source.isParameter()) json.addProperty("parameter_index", source.getCategoryIndex());
        var storage = source.getStorage();
        json.addProperty("storage", storage == null ? null : storage.toString());
        ghidra.program.model.symbol.Symbol database = source.getSymbol();
        if (database != null) {
            json.addProperty("database_id", Long.toString(database.getID()));
            json.addProperty("symbol_type", database.getSymbolType().toString());
            address(json, "address", database.getAddress());
        }
        JsonArray variables = selectedIds(symbol.variables);
        json.add("high_variables", variables);
        json.add("high_variables_status", counts(variables.size(), symbol.variables.size()));
        return json;
    }

    private JsonObject storage(Varnode value) {
        JsonObject json = new JsonObject();
        AddressSpace space = value.getAddress().getAddressSpace();
        json.addProperty("space", space.getName());
        json.addProperty("space_type", space.getType());
        json.addProperty("offset", "0x" + Long.toHexString(value.getOffset()));
        json.addProperty("size", value.getSize());
        String type = value.isConstant() ? "constant" : value.isRegister() ? "register"
            : value.isUnique() ? "unique" : space.isStackSpace() ? "stack"
            : space.isMemorySpace() ? "memory" : space.isVariableSpace() ? "join"
            : space.isExternalSpace() ? "external" : space.isHashSpace() ? "hash" : "other";
        json.addProperty("type", type);
        if (value.isRegister()) {
            Register register = session.program().getRegister(value);
            if (register != null) json.addProperty("register", register.getName());
        }
        return json;
    }

    private JsonObject ref(HighPcodeModel.Node node, String missing) {
        JsonObject reference = new JsonObject();
        reference.addProperty("id", node == null ? null : node.id);
        reference.addProperty("state", node == null ? missing : selected.contains(node) ? "included" : "omitted");
        return reference;
    }

    private JsonObject edgeRef(HighPcodeModel.Edge edge) {
        JsonObject reference = new JsonObject();
        reference.addProperty("id", edge == null ? null : edge.id);
        reference.addProperty("state", edge == null ? "unresolved" : selectedEdges.contains(edge) ? "included" : "omitted");
        return reference;
    }

    private JsonArray selectedIds(List<? extends HighPcodeModel.Node> nodes) throws CancelledException {
        JsonArray ids = new JsonArray();
        for (HighPcodeModel.Node node : nodes) {
            session.monitor().checkCancelled();
            if (selected.contains(node)) ids.add(node.id);
        }
        return ids;
    }

    private JsonArray selectedEdgeIds(List<HighPcodeModel.Edge> edges) throws CancelledException {
        JsonArray ids = new JsonArray();
        for (HighPcodeModel.Edge edge : edges) {
            session.monitor().checkCancelled();
            if (selectedEdges.contains(edge)) ids.add(edge.id);
        }
        return ids;
    }

    private static JsonObject node(HighPcodeModel.Node node) {
        JsonObject json = new JsonObject();
        json.addProperty("id", node.id);
        return json;
    }

    private static JsonObject counts(long returned, long total) {
        JsonObject json = new JsonObject();
        json.addProperty("returned", returned);
        json.addProperty("total", total);
        json.addProperty("complete", returned == total);
        return json;
    }

    private static void dataType(JsonObject json, DataType type) {
        json.addProperty("type", type == null ? null : type.getName());
        json.addProperty("type_path", type == null ? null : type.getPathName());
    }

    private static void address(JsonObject json, String key, Address address) {
        json.addProperty(key, address == null || address == Address.NO_ADDRESS ? null : AddressCodec.format(address));
    }
}
