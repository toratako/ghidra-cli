package ghidracli;

import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeBlock;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.List;

/** Request-local identity and def/use index. Output selection never modifies this model. */
final class HighPcodeModel {
    abstract static class Node {
        final String id;
        Node(String id) { this.id = id; }
        abstract long relationshipCount();
    }

    static final class Operation extends Node {
        final PcodeOp source;
        final Block block;
        final Integer blockOrder;
        Operation(PcodeOp source, Block block, Integer blockOrder, int index) {
            super("op" + index);
            this.source = source;
            this.block = block;
            this.blockOrder = blockOrder;
        }
        long relationshipCount() {
            return (long) source.getNumInputs() + (source.getOutput() == null ? 0 : 1)
                + (block == null ? 0 : 1);
        }
    }

    static final class Use {
        final Operation operation;
        final int slot;
        Use(Operation operation, int slot) { this.operation = operation; this.slot = slot; }
    }

    static final class Value extends Node {
        final Varnode source;
        final List<Use> uses = new ArrayList<>();
        Variable variable;
        Value(Varnode source, int index) { super("v" + index); this.source = source; }
        long relationshipCount() { return variable == null ? 0 : 1; }
    }

    static final class Block extends Node {
        final PcodeBlockBasic source;
        final List<Operation> operations = new ArrayList<>();
        final List<Edge> incoming = new ArrayList<>();
        final List<Edge> outgoing = new ArrayList<>();
        Block(PcodeBlockBasic source, int index) { super("b" + index); this.source = source; }
        long relationshipCount() { return 0; }
    }

    static final class Variable extends Node {
        final HighVariable source;
        final List<Value> instances = new ArrayList<>();
        Value representative;
        Symbol symbol;
        Variable(HighVariable source, int index) { super("h" + index); this.source = source; }
        long relationshipCount() {
            return (representative == null ? 0 : 1) + (symbol == null ? 0 : 1);
        }
    }

    static final class Symbol extends Node {
        final HighSymbol source;
        final List<Variable> variables = new ArrayList<>();
        Symbol(HighSymbol source, int index) { super("s" + index); this.source = source; }
        long relationshipCount() { return 0; }
    }

    static final class Edge {
        final String id;
        final Block source;
        final Block target;
        final int sourceOutIndex;
        final int targetInIndex;
        Edge(Block source, Block target, int sourceOutIndex, int targetInIndex, int index) {
            this.id = "e" + index;
            this.source = source;
            this.target = target;
            this.sourceOutIndex = sourceOutIndex;
            this.targetInIndex = targetInIndex;
        }
    }

    final HighFunction source;
    final List<Node> order = new ArrayList<>();
    final List<Operation> operations = new ArrayList<>();
    final List<Value> values = new ArrayList<>();
    final List<Block> blocks = new ArrayList<>();
    final List<Variable> variables = new ArrayList<>();
    final List<Symbol> symbols = new ArrayList<>();
    final List<Edge> edges = new ArrayList<>();
    final IdentityHashMap<PcodeOp, Operation> operationIndex = new IdentityHashMap<>();
    final IdentityHashMap<Varnode, Value> valueIndex = new IdentityHashMap<>();
    final IdentityHashMap<PcodeBlock, Block> blockIndex = new IdentityHashMap<>();
    final IdentityHashMap<HighVariable, Variable> variableIndex = new IdentityHashMap<>();
    final IdentityHashMap<HighSymbol, Symbol> symbolIndex = new IdentityHashMap<>();
    long relationshipCount;

    private HighPcodeModel(HighFunction source) { this.source = source; }

    static HighPcodeModel build(HighFunction source, TaskMonitor monitor) throws CancelledException {
        HighPcodeModel model = new HighPcodeModel(source);
        // Native block iteration is execution order. Sequence time is an identity component,
        // not a substitute for this order. Decoded PcodeOpAST.isDead() is not a liveness test.
        for (PcodeBlockBasic block : source.getBasicBlocks()) {
            monitor.checkCancelled();
            // The decoder addresses this list by native block index and can leave gaps.
            if (block == null) continue;
            Block indexed = model.block(block);
            Iterator<PcodeOp> iterator = block.getIterator();
            int blockOrder = 0;
            while (iterator.hasNext()) {
                monitor.checkCancelled();
                model.operation(iterator.next(), indexed, blockOrder++, monitor);
            }
        }
        for (Block block : model.blocks) {
            for (int i = 0; i < block.source.getOutSize(); i++) {
                monitor.checkCancelled();
                Block target = model.blockIndex.get(block.source.getOut(i));
                Edge edge = new Edge(block, target, i, block.source.getOutRevIndex(i), model.edges.size());
                model.edges.add(edge);
                block.outgoing.add(edge);
                if (target != null) target.incoming.add(edge);
            }
        }
        // Incoming edge order is semantic: MULTIEQUAL input i belongs to incoming edge i.
        for (Block block : model.blocks) {
            monitor.checkCancelled();
            block.incoming.sort((a, b) -> Integer.compare(a.targetInIndex, b.targetInIndex));
        }
        model.relationshipCount = model.edges.size();
        for (Node node : model.order) {
            monitor.checkCancelled();
            model.relationshipCount += node.relationshipCount();
        }
        return model;
    }

    private Block block(PcodeBlockBasic source) {
        Block existing = blockIndex.get(source);
        if (existing != null) return existing;
        Block block = new Block(source, blocks.size());
        blockIndex.put(source, block);
        blocks.add(block);
        order.add(block);
        return block;
    }

    private void operation(PcodeOp source, Block block, Integer blockOrder, TaskMonitor monitor)
            throws CancelledException {
        if (operationIndex.containsKey(source)) return;
        Operation op = new Operation(source, block, blockOrder, operations.size());
        operationIndex.put(source, op);
        operations.add(op);
        order.add(op);
        if (block != null) block.operations.add(op);
        value(source.getOutput(), monitor);
        for (int i = 0; i < source.getNumInputs(); i++) {
            monitor.checkCancelled();
            // IOP references and LOAD/STORE space encodings are not values or data uses.
            if (isOperationReference(source, i) || isSpaceReference(source, i)) continue;
            Value value = value(source.getInput(i), monitor);
            if (value != null) value.uses.add(new Use(op, i));
        }
    }

    private Value value(Varnode source, TaskMonitor monitor) throws CancelledException {
        if (source == null) return null;
        Value existing = valueIndex.get(source);
        if (existing != null) return existing;
        monitor.checkCancelled();
        Value value = new Value(source, values.size());
        valueIndex.put(source, value);
        values.add(value);
        order.add(value);
        value.variable = variable(source.getHigh(), monitor);
        if (value.variable != null) value.variable.instances.add(value);
        return value;
    }

    private Variable variable(HighVariable source, TaskMonitor monitor) throws CancelledException {
        if (source == null) return null;
        Variable existing = variableIndex.get(source);
        if (existing != null) return existing;
        monitor.checkCancelled();
        Variable variable = new Variable(source, variables.size());
        variableIndex.put(source, variable);
        variables.add(variable);
        order.add(variable);
        variable.symbol = symbol(source.getSymbol());
        if (variable.symbol != null) variable.symbol.variables.add(variable);
        variable.representative = value(source.getRepresentative(), monitor);
        // Symbol.getHighVariable() exposes only one (largest) partial variable. Walk
        // each value's HighVariable and every native instance to preserve partials.
        Varnode[] instances = source.getInstances();
        if (instances != null) {
            for (Varnode instance : instances) value(instance, monitor);
        }
        return variable;
    }

    private Symbol symbol(HighSymbol source) {
        if (source == null) return null;
        Symbol existing = symbolIndex.get(source);
        if (existing != null) return existing;
        Symbol symbol = new Symbol(source, symbols.size());
        symbolIndex.put(source, symbol);
        symbols.add(symbol);
        order.add(symbol);
        return symbol;
    }

    static boolean isOperationReference(PcodeOp op, int slot) {
        return op.getOpcode() == PcodeOp.INDIRECT && slot == 1;
    }

    static boolean isSpaceReference(PcodeOp op, int slot) {
        return (op.getOpcode() == PcodeOp.LOAD || op.getOpcode() == PcodeOp.STORE) && slot == 0;
    }

    static String inputRole(PcodeOp op, int slot) {
        switch (op.getOpcode()) {
            case PcodeOp.LOAD: return slot == 0 ? "address_space" : "address";
            case PcodeOp.STORE:
                return slot == 0 ? "address_space" : slot == 1 ? "address" : "stored_value";
            case PcodeOp.INDIRECT: return slot == 1 ? "operation_reference" : "prior_value";
            case PcodeOp.CALL:
            case PcodeOp.CALLIND: return slot == 0 ? "call_target" : "argument";
            case PcodeOp.BRANCH:
            case PcodeOp.BRANCHIND: return "branch_target";
            case PcodeOp.CBRANCH: return slot == 0 ? "branch_target" : "condition";
            case PcodeOp.RETURN: return slot == 0 ? "return_target" : "return_value";
            case PcodeOp.MULTIEQUAL: return "phi_input";
            case PcodeOp.CALLOTHER: return slot == 0 ? "userop_id" : "argument";
            default: return "value";
        }
    }
}
