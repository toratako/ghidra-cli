package ghidracli.analysis;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.SimpleDestReferenceIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionPcodeOverride;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import ghidra.util.exception.CancelledException;
import ghidracli.function.FunctionQueries;
import ghidracli.listing.InstructionFlow;
import ghidracli.query.AddressCodec;
import ghidracli.session.ProgramSession;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static ghidracli.protocol.JsonProtocol.errorResult;
import static ghidracli.protocol.JsonProtocol.getArgString;

/** Listing CFGs. Native blocks, and all native objects below, live for one request only. */
public final class InstructionCfg {
    private final ProgramSession session;
    private final FunctionQueries functions;

    public InstructionCfg(ProgramSession session, FunctionQueries functions) {
        this.session = session;
        this.functions = functions;
    }

    public JsonObject handle(JsonObject args) throws CancelledException {
        if (session.program() == null) return errorResult("No program loaded");
        AnalysisLimits limits = AnalysisLimits.from(args);
        String target = getArgString(args, "function");
        if (target == null || target.isBlank()) return errorResult("Function target required");
        Function function = functions.findFunctionByNameOrAddress(target);
        if (function == null) return errorResult(functions.buildFunctionTargetHint(target));
        return new Capture(function, limits).run();
    }

    private record Block(CodeBlock nativeBlock, String id, JsonObject json) {}
    private record FlowKey(String from, Address site, Address target, String type, String kind) {}

    /** A capture owns its model, identity map, traversal counters and output budget. */
    private final class Capture {
        private final Function function;
        private final AddressSetView body;
        private final AnalysisLimits limits;
        private final List<Block> blocks = new ArrayList<>();
        private final JsonArray nodes = new JsonArray();
        private final JsonArray edges = new JsonArray();
        private final JsonArray calls = new JsonArray();
        private final JsonArray boundaries = new JsonArray();
        private final Set<FlowKey> emitted = new HashSet<>();
        private boolean blocksComplete = true;
        private boolean flowsComplete = true;
        private long instructionsScanned;
        private long referencesScanned;

        Capture(Function function, AnalysisLimits limits) {
            this.function = function;
            this.body = function.getBody();
            this.limits = limits;
        }

        JsonObject run() throws CancelledException {
            JsonObject result = AnalysisContext.create(session, function, "instruction_cfg");
            result.addProperty("model", "basic_block");
            result.add("limits", limits.toJson("blocks", "transitions_calls_boundaries"));
            // Include native external references, without traversing their destination blocks.
            BasicBlockModel model = new BasicBlockModel(session.program(), true);
            var iterator = model.getCodeBlocksContaining(body, session.monitor());
            while (iterator.hasNext()) {
                session.monitor().checkCancelled();
                if (blocks.size() == limits.maxNodes()) {
                    blocksComplete = false;
                    break;
                }
                CodeBlock nativeBlock = iterator.next();
                JsonObject row = new JsonObject();
                String id = "b" + blocks.size();
                row.addProperty("id", id);
                JsonArray entries = new JsonArray();
                for (Address address : nativeBlock.getStartAddresses()) {
                    session.monitor().checkCancelled();
                    entries.add(AddressCodec.format(address));
                }
                row.add("entries", entries);
                row.add("ranges", AnalysisContext.ranges(nativeBlock, session.monitor()));
                row.add("body_intersection", AnalysisContext.ranges(nativeBlock.intersect(body), session.monitor()));
                row.addProperty("flows_complete", false);
                blocks.add(new Block(nativeBlock, id, row));
                nodes.add(row);
            }

            for (Block block : blocks) {
                session.monitor().checkCancelled();
                if (!flowsComplete) break;
                scan(block);
                block.json().addProperty("flows_complete", flowsComplete);
            }
            result.add("nodes", nodes);
            result.add("edges", edges);
            result.add("calls", calls);
            result.add("boundaries", boundaries);
            JsonObject completion = new JsonObject();
            boolean complete = blocksComplete && flowsComplete;
            JsonArray reasons = new JsonArray();
            if (!blocksComplete) reasons.add("max_nodes");
            if (!flowsComplete) reasons.add("max_edges");
            JsonObject scanned = new JsonObject();
            scanned.addProperty("complete", complete);
            scanned.addProperty("blocks", blocks.size());
            scanned.addProperty("instructions", instructionsScanned);
            scanned.addProperty("references", referencesScanned);
            completion.add("scan", scanned);
            JsonObject output = new JsonObject();
            output.addProperty("complete", complete);
            output.addProperty("nodes", nodes.size());
            output.addProperty("edges", edges.size() + calls.size() + boundaries.size());
            output.add("reasons", reasons);
            completion.add("output", output);
            JsonObject collections = new JsonObject();
            collections.add("nodes", count(nodes, blocksComplete));
            collections.add("edges", count(edges, complete));
            collections.add("calls", count(calls, complete));
            collections.add("boundaries", count(boundaries, complete));
            completion.add("collections", collections);
            result.add("completion", completion);
            return result;
        }

        private JsonObject count(JsonArray rows, boolean complete) {
            JsonObject counts = new JsonObject();
            counts.addProperty("returned", rows.size());
            counts.addProperty("complete", complete);
            if (complete) counts.addProperty("total", rows.size());
            return counts;
        }

        private void scan(Block block) throws CancelledException {
            Set<Address> knownCalls = new HashSet<>();
            Set<Address> knownJumps = new HashSet<>();
            // Ghidra eagerly gathers this block's references. Output caps do not bound that
            // native work; its request monitor supplies cancellation throughout collection.
            // Native indirection inference follows any primitive containing the
            // operand, including integer data and interior pointer bytes. Keep
            // native literal flows, then resolve pointers through our checked path.
            var destinations = new SimpleDestReferenceIterator(
                block.nativeBlock(), false, session.monitor());
            while (destinations.hasNext()) {
                session.monitor().checkCancelled();
                var reference = destinations.next();
                referencesScanned++;
                Address site = reference.getReferent();
                Address target = reference.getReference();
                FlowType type = reference.getFlowType();
                Instruction instruction = session.program().getListing().getInstructionAt(site);
                if (instruction == null) continue;
                if (type.isCall() && !isCallReference(instruction, target, type)) continue;
                if (type.isJump() && !isJumpReference(instruction, target, type)) continue;
                if (type.isFallthrough() && !target.equals(instruction.getFallThrough())) continue;
                if (type == RefType.INDIRECTION) {
                    // This is an operand pointer, not an instruction destination.
                    FlowType effective = instruction.getFlowType();
                    if (!hasIndirectFlow(instruction)) continue;
                    boolean call = effective.isCall();
                    boolean resolved = supplementPointer(block, instruction);
                    if (!flowsComplete) return;
                    if (!resolved && !emit(block, site, null, effective,
                            call ? "call" : "unresolved", target)) return;
                    (call ? knownCalls : knownJumps).add(site);
                } else {
                    boolean call = type.isCall();
                    if (!emit(block, site, target, type, call ? "call" : "edge", null)) return;
                    if (call) knownCalls.add(site);
                    else if (type.isJump()) knownJumps.add(site);
                }
            }

            var instructions = session.program().getListing().getInstructions(block.nativeBlock(), true);
            while (instructions.hasNext()) {
                session.monitor().checkCancelled();
                Instruction instruction = instructions.next();
                instructionsScanned++;
                Address site = instruction.getMinAddress();
                FlowType type = instruction.getFlowType();
                Set<Address> known = type.isCall() ? knownCalls : knownJumps;
                if ((type.isCall() || type.isJump()) && !known.contains(site)) {
                    boolean resolved = false;
                    // getFlows includes inert/nonprimary override references.
                    // Effective p-code supplies only actual direct targets.
                    for (Address target : directTargets(instruction, type.isCall())) {
                        session.monitor().checkCancelled();
                        if (!emit(block, site, target, type, type.isCall() ? "call" : "edge", null)) return;
                        resolved = true;
                    }
                    if (!resolved && type.isComputed()) {
                        resolved = supplementPointer(block, instruction);
                        if (!flowsComplete) return;
                    }
                    if (!resolved && !emit(block, site, null, type,
                            type.isCall() ? "call" : "unresolved", null)) return;
                }

                // Delay-slot execution is part of the native block even if its bytes lie
                // outside this function's body. Preserve that physical boundary separately.
                Instruction previous = instruction;
                for (int slot = 0; slot < instruction.getDelaySlotDepth(); slot++) {
                    session.monitor().checkCancelled();
                    Instruction next = previous.getNext();
                    if (next == null) break;
                    if (crosses(previous.getMinAddress(), next.getMinAddress())
                            && !emit(block, previous.getMinAddress(), next.getMinAddress(),
                                RefType.FALL_THROUGH, "delay_slot", null)) return;
                    previous = next;
                }

                // A delay-slot instruction does not independently continue past a terminal
                // branch. The branch's effective fallthrough already accounts for its slots.
                if (!instruction.isInDelaySlot()) {
                    Address fallthrough = instruction.getFallThrough();
                    if (fallthrough != null) {
                        if (!block.nativeBlock().contains(fallthrough)) {
                            if (!emit(block, site, fallthrough, RefType.FALL_THROUGH, "edge", null)) return;
                        } else if (crosses(site, fallthrough)) {
                            if (!emit(block, site, fallthrough, RefType.FALL_THROUGH, "body_crossing", null)) return;
                        }
                    }
                    if (type.isTerminal()) {
                        if (!emit(block, site, null, type, "terminal", null)) return;
                    } else if (fallthrough == null && !type.isJump() && !type.isCall()) {
                        if (!emit(block, site, null, type, "no_fallthrough", null)) return;
                    }
                }
            }
        }

        /** Resolve computed transfers only through exact typed pointer operands. */
        private boolean supplementPointer(Block block, Instruction instruction) throws CancelledException {
            if (!hasIndirectFlow(instruction)) return false;
            boolean resolved = false;
            for (var reference : instruction.getReferencesFrom()) {
                session.monitor().checkCancelled();
                referencesScanned++;
                RefType type = reference.getReferenceType();
                if (!(type.isRead() || type == RefType.DATA || type == RefType.INDIRECTION)) continue;
                Address via = reference.getToAddress();
                // A reference can identify only an encoded table base while a
                // runtime register selects the actual slot. Native operand
                // addresses exist only for statically resolved memory operands.
                Address operandAddress = instruction.getPrototype().getAddress(
                    reference.getOperandIndex(), instruction.getInstructionContext());
                if (!via.equals(operandAddress)) continue;
                var data = session.program().getListing().getDefinedDataContaining(via);
                if (data == null) continue;
                long offset = via.subtract(data.getMinAddress());
                if (offset > Integer.MAX_VALUE) continue;
                var pointer = data.getPrimitiveAt((int) offset);
                // Interior bytes belong to the same primitive but do not load its
                // pointer value. Only the primitive's start supplies this evidence.
                if (pointer == null || !pointer.isPointer() || !pointer.getAddress().equals(via)) continue;
                for (var destination : session.program().getReferenceManager().getReferencesFrom(via)) {
                    session.monitor().checkCancelled();
                    referencesScanned++;
                    RefType pointerType = destination.getReferenceType();
                    if (!(pointerType == RefType.DATA || pointerType == RefType.INDIRECTION
                            || destination.isExternalReference())) continue;
                    FlowType flow = instruction.getFlowType();
                    if (!emit(block, instruction.getMinAddress(), destination.getToAddress(), flow,
                            flow.isCall() ? "call" : "edge", via)) return false;
                    resolved = true;
                }
            }
            return resolved;
        }

        private boolean isCallReference(Instruction instruction, Address target, FlowType type)
                throws CancelledException {
            for (var reference : instruction.getReferencesFrom()) {
                session.monitor().checkCancelled();
                if (reference.getReferenceType().equals(type) && reference.getToAddress().equals(target)
                        && InstructionFlow.isCallReference(instruction, reference)) return true;
            }
            return false;
        }

        private boolean hasIndirectFlow(Instruction instruction) throws CancelledException {
            FlowType flow = instruction.getFlowType();
            int opcode = flow.isCall() ? PcodeOp.CALLIND : flow.isJump() ? PcodeOp.BRANCHIND : -1;
            if (opcode == -1) return false;
            for (PcodeOp op : InstructionFlow.effectivePcode(instruction)) {
                session.monitor().checkCancelled();
                if (op.getOpcode() == opcode) return true;
            }
            return false;
        }

        private boolean isJumpReference(Instruction instruction, Address target, FlowType type)
                throws CancelledException {
            for (var reference : instruction.getReferencesFrom()) {
                session.monitor().checkCancelled();
                if (!reference.getReferenceType().equals(type)
                        || !reference.getToAddress().equals(target)) continue;
                if (type.isOverride()) {
                    if (!reference.isPrimary() || !target.equals(new InstructionPcodeOverride(instruction)
                            .getOverridingReference(reference.getReferenceType()))) continue;
                } else {
                    if (!instruction.getFlowType().isJump()) continue;
                    if (reference.isExternalReference()) {
                        InstructionPcodeOverride override = new InstructionPcodeOverride(instruction);
                        instruction.getPrototype().getPcode(instruction.getInstructionContext(), override);
                        // An applied jump override supersedes symbolic external
                        // relocation evidence just as it supersedes memory targets.
                        if (!override.isJumpOverrideRefApplied()) return true;
                        continue;
                    }
                }
                for (PcodeOp op : InstructionFlow.effectivePcode(instruction)) {
                    session.monitor().checkCancelled();
                    if ((op.getOpcode() == PcodeOp.BRANCH || op.getOpcode() == PcodeOp.CBRANCH)
                            && op.getNumInputs() > 0 && !op.getInput(0).isConstant()
                            && target.equals(op.getInput(0).getAddress())) return true;
                    if (!type.isOverride() && op.getOpcode() == PcodeOp.BRANCHIND) return true;
                }
            }
            return false;
        }

        private List<Address> directTargets(Instruction instruction, boolean call) throws CancelledException {
            List<Address> targets = new ArrayList<>();
            for (PcodeOp op : InstructionFlow.effectivePcode(instruction)) {
                session.monitor().checkCancelled();
                boolean transfer = call ? op.getOpcode() == PcodeOp.CALL
                    : op.getOpcode() == PcodeOp.BRANCH || op.getOpcode() == PcodeOp.CBRANCH;
                if (transfer && op.getNumInputs() > 0 && !op.getInput(0).isConstant()) {
                    targets.add(op.getInput(0).getAddress());
                }
            }
            return targets;
        }

        private boolean crosses(Address site, Address target) {
            return site != null && target != null && body.contains(site) != body.contains(target);
        }

        /** One shared cap includes boundary evidence and unresolved transfers; no free stubs. */
        private boolean emit(Block block, Address site, Address target, FlowType type, String kind,
                Address via) throws CancelledException {
            session.monitor().checkCancelled();
            FlowKey key = new FlowKey(block.id(), site, target, type.toString(), kind);
            if (emitted.contains(key)) return true;
            if (edges.size() + calls.size() + boundaries.size() >= limits.maxEdges()) {
                flowsComplete = false;
                return false;
            }
            emitted.add(key);
            JsonObject row = new JsonObject();
            row.addProperty("from", block.id());
            row.addProperty("site", AddressCodec.format(site));
            row.addProperty("target", AddressCodec.format(target));
            row.addProperty("flow_type", type.toString());
            row.addProperty("site_in_body", site != null && body.contains(site));
            row.addProperty("target_in_body", target == null ? null : body.contains(target));
            row.addProperty("body_crossing", !crosses(site, target) ? null
                : body.contains(site) ? "exit" : "entry");
            if (via != null) row.addProperty("via", AddressCodec.format(via));
            Block destination = null;
            if (target != null) {
                for (Block candidate : blocks) {
                    session.monitor().checkCancelled();
                    if (candidate.nativeBlock().contains(target)) {
                        destination = candidate;
                        break;
                    }
                }
            }
            row.addProperty("to", destination == null ? null : destination.id());
            String state;
            if (target == null) state = kind.equals("terminal") || kind.equals("no_fallthrough")
                ? "not_applicable" : "unresolved";
            else if (target.isExternalAddress()) state = "external";
            else if (session.program().getListing().getInstructionAt(target) == null) state = "missing_instruction";
            else if (destination != null) state = "included";
            else if (!body.contains(target)) state = "outside_function";
            else state = !blocksComplete ? "omitted" : "not_examined";
            // A known address within a byte range is not necessarily an instruction start.
            if (!state.equals("included")) row.addProperty("to", (String) null);
            row.addProperty("target_state", state);
            if (kind.equals("call")) calls.add(row);
            else if (kind.equals("edge")) edges.add(row);
            else {
                row.addProperty("kind", kind);
                boundaries.add(row);
            }
            return true;
        }
    }
}
