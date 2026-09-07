package ghidracli;

import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.task.TaskMonitor;
import java.util.Iterator;
import static ghidracli.JsonProtocol.errorResult;
import static ghidracli.JsonProtocol.getArgString;

final class PcodeCommands {
    private final ProgramSession session;
    private final AddressResolver addressResolver;
    private final FunctionQueries functionQueries;

    PcodeCommands(ProgramSession session, AddressResolver addressResolver, FunctionQueries functionQueries) {
        this.session = session;
        this.addressResolver = addressResolver;
        this.functionQueries = functionQueries;
    }

    JsonObject handlePcodeAt(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String addrStr = getArgString(args, "address");
        if (addrStr == null || addrStr.isEmpty()) return errorResult("address required");

        try {
            Address addr = addressResolver.resolveAddress(addrStr);
            if (addr == null) return errorResult("Invalid address: " + addrStr);

            Instruction inst = session.program().getListing().getInstructionAt(addr);
            if (inst == null) return errorResult("No instruction at address: " + addrStr);

            JsonArray ops = new JsonArray();
            for (PcodeOp op : inst.getPcode()) ops.add(pcodeOpToJson(op));

            JsonObject result = new JsonObject();
            result.addProperty("address", addr.toString());
            result.addProperty("mnemonic", inst.getMnemonicString());
            result.addProperty("instruction", inst.toString());
            result.addProperty("count", ops.size());
            result.add("pcode", ops);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to get PCode: " + e.getMessage());
        }
    }

    JsonObject handlePcodeFunction(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String target = getArgString(args, "function");
        boolean highPcode = args.has("high") && args.get("high").getAsBoolean();
        if (target == null || target.isEmpty()) return errorResult("function name or address required");

        try {
            Function func = functionQueries.findFunctionByNameOrAddress(target);
            if (func == null) return errorResult(functionQueries.buildFunctionTargetHint(target));

            JsonArray ops = new JsonArray();
            if (highPcode) {
                DecompInterface decomp = new DecompInterface();
                try {
                    if (!decomp.openProgram(session.program())) {
                        return errorResult("Decompilation failed: openProgram failed: " + decomp.getLastMessage());
                    }
                    DecompileResults results = decomp.decompileFunction(func, 30, TaskMonitor.DUMMY);
                    if (!results.decompileCompleted()) {
                        String reason = results.getErrorMessage();
                        if (reason == null || reason.isEmpty()) reason = "unknown failure";
                        return errorResult("Decompilation failed for " + func.getName() + ": " + reason);
                    }

                    HighFunction highFunction = results.getHighFunction();
                    if (highFunction == null) {
                        return errorResult("Decompiler returned no HighFunction for " + func.getName());
                    }
                    Iterator<PcodeOpAST> it = highFunction.getPcodeOps();
                    while (it.hasNext()) ops.add(pcodeOpToJson(it.next()));
                } finally {
                    decomp.dispose();
                }
            } else {
                InstructionIterator instructions =
                    session.program().getListing().getInstructions(func.getBody(), true);
                while (instructions.hasNext()) {
                    Instruction inst = instructions.next();
                    for (PcodeOp op : inst.getPcode()) {
                        JsonObject opJson = pcodeOpToJson(op);
                        opJson.addProperty("instruction_address", inst.getAddress().toString());
                        ops.add(opJson);
                    }
                }
            }

            JsonObject result = new JsonObject();
            result.addProperty("function", func.getName());
            result.addProperty("address", func.getEntryPoint().toString());
            result.addProperty("level", highPcode ? "high" : "raw");
            result.addProperty("count", ops.size());
            result.add("pcode", ops);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to get function PCode: " + e.getMessage());
        }
    }

    private JsonObject pcodeOpToJson(PcodeOp op) {
        JsonObject obj = new JsonObject();
        obj.addProperty("mnemonic", op.getMnemonic());
        obj.addProperty("opcode", op.getOpcode());

        Varnode output = op.getOutput();
        if (output != null) obj.add("output", varnodeToJson(output));
        else obj.add("output", JsonNull.INSTANCE);

        JsonArray inputs = new JsonArray();
        for (int i = 0; i < op.getNumInputs(); i++) inputs.add(varnodeToJson(op.getInput(i)));
        obj.add("inputs", inputs);
        return obj;
    }

    private JsonObject varnodeToJson(Varnode vn) {
        JsonObject obj = new JsonObject();
        obj.addProperty("space", vn.getAddress().getAddressSpace().getName());
        obj.addProperty("offset", "0x" + Long.toHexString(vn.getOffset()));
        obj.addProperty("size", vn.getSize());
        if (vn.isConstant()) {
            obj.addProperty("type", "constant");
        } else if (vn.isRegister()) {
            obj.addProperty("type", "register");
            Register reg = session.program().getRegister(vn);
            if (reg != null) obj.addProperty("register", reg.getName());
        } else if (vn.isUnique()) {
            obj.addProperty("type", "unique");
        } else if (vn.getAddress().isStackAddress()) {
            obj.addProperty("type", "stack");
        } else {
            obj.addProperty("type", "ram");
        }
        return obj;
    }
}
