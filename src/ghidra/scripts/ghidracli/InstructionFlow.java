package ghidracli;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.FlowType;

/** Native instruction interpretation shared by flow edits and call-site queries. */
final class InstructionFlow {
    private InstructionFlow() {}

    static PcodeOp[] effectivePcode(Instruction instruction) {
        return instruction.getPcode(true);
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
