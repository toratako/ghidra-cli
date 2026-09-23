package ghidracli.listing;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionPcodeOverride;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;

/** Native instruction interpretation shared by flow edits and call-site queries. */
public final class InstructionFlow {
    private InstructionFlow() {}

    public static PcodeOp[] effectivePcode(Instruction instruction) {
        return instruction.getPcode(true);
    }

    /** A saved CALL reference must describe a call the instruction actually makes. */
    public static boolean isCallReference(Instruction instruction, Reference reference) {
        if (instruction == null) return false;
        RefType type = reference.getReferenceType();
        if (!type.isCall()) return false;
        if (type.isOverride()) {
            // Native overrides require one primary reference of this type.
            // Even a primary override is inert on e.g. a NOP, or when a
            // different native override takes precedence.
            if (!reference.isPrimary() || !reference.getToAddress().equals(
                    new InstructionPcodeOverride(instruction).getOverridingReference(type))) {
                return false;
            }
        } else if (!instruction.getFlowType().isCall()) {
            return false;
        } else if (reference.isExternalReference()) {
            // External relocation metadata is not a memory-space p-code
            // override. Graph queries still need these symbolic callees.
            return true;
        }
        for (PcodeOp op : effectivePcode(instruction)) {
            if (op.getOpcode() == PcodeOp.CALL && op.getNumInputs() > 0
                    && reference.getToAddress().equals(op.getInput(0).getAddress())) {
                return true;
            }
            // Computed calls can have several recorded resolved destinations.
            // A reference override resolves CALLIND to CALL, so old targets
            // do not survive an effective direct-call override.
            if (!type.isOverride() && op.getOpcode() == PcodeOp.CALLIND) return true;
        }
        return false;
    }

    static FlowType rawFlowType(Instruction instruction) {
        return instruction.getPrototype().getFlowType(instruction.getInstructionContext());
    }

    static Address rawFallthrough(Instruction instruction) {
        return instruction.getPrototype().getFallThrough(instruction.getInstructionContext());
    }

    static boolean hasRawTransfer(Instruction instruction) {
        FlowType flow = rawFlowType(instruction);
        // CMOV/REP have internal p-code branches to memory-space inst_next/inst_start,
        // but the instruction itself only falls through and has no overridable transfer.
        if (!flow.isJump() && !flow.isCall() && !flow.isTerminal()) return false;
        for (PcodeOp op : instruction.getPcode()) {
            switch (op.getOpcode()) {
                case PcodeOp.CALL:
                case PcodeOp.CALLIND:
                case PcodeOp.BRANCHIND:
                case PcodeOp.RETURN:
                    return true;
                case PcodeOp.BRANCH:
                case PcodeOp.CBRANCH:
                    // HLT is terminal with an internal branch to inst_start, not a RETURN.
                    // Do not compare resolved addresses: a real JMP to itself/next is valid.
                    if (flow.isJump() && op.getNumInputs() > 0
                            && !op.getInput(0).isConstant()) return true;
                    break;
                default:
                    break;
            }
        }
        return false;
    }
}
