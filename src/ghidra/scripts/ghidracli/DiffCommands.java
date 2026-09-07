package ghidracli;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.task.TaskMonitor;
import static ghidracli.JsonProtocol.errorResult;
import static ghidracli.JsonProtocol.getArgString;

final class DiffCommands {
    private final ProgramSession session;
    private final FunctionQueries functionQueries;

    DiffCommands(ProgramSession session, FunctionQueries functionQueries) {
        this.session = session;
        this.functionQueries = functionQueries;
    }

    JsonObject handleDiffPrograms(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String prog1 = getArgString(args, "program1");
        String prog2 = getArgString(args, "program2");
        if (prog1 == null) prog1 = "";
        if (prog2 == null) prog2 = "";

        try {
            FunctionManager fm = session.program().getFunctionManager();
            Memory memory = session.program().getMemory();
            SymbolTable symbolTable = session.program().getSymbolTable();

            JsonObject prog1Stats = new JsonObject();
            prog1Stats.addProperty("name", prog1);
            prog1Stats.addProperty("function_count", fm.getFunctionCount());
            prog1Stats.addProperty("memory_size", memory.getSize());
            prog1Stats.addProperty("symbol_count", symbolTable.getNumSymbols());

            JsonArray memBlocks = new JsonArray();
            for (MemoryBlock block : memory.getBlocks()) {
                JsonObject blockObj = new JsonObject();
                blockObj.addProperty("name", block.getName());
                blockObj.addProperty("start", block.getStart().toString());
                blockObj.addProperty("end", block.getEnd().toString());
                blockObj.addProperty("size", block.getSize());
                memBlocks.add(blockObj);
            }
            prog1Stats.add("memory_blocks", memBlocks);

            JsonObject prog2Stats = new JsonObject();
            prog2Stats.addProperty("name", prog2);
            prog2Stats.addProperty("note", "Comparison requires loading second program");

            JsonObject result = new JsonObject();
            result.add("program1", prog1Stats);
            result.add("program2", prog2Stats);
            result.addProperty("status", "partial");
            result.addProperty("message", "Single program stats returned (multi-program comparison not implemented)");
            return result;
        } catch (Exception e) {
            return errorResult("Failed to diff programs: " + e.getMessage());
        }
    }

    JsonObject handleDiffFunctions(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String func1Target = getArgString(args, "func1");
        String func2Target = getArgString(args, "func2");
        if (func1Target == null || func2Target == null) {
            return errorResult("func1 and func2 required");
        }

        try {
            Function func1 = functionQueries.findFunctionByNameOrAddress(func1Target);
            Function func2 = functionQueries.findFunctionByNameOrAddress(func2Target);

            if (func1 == null) return errorResult(functionQueries.buildFunctionTargetHint(func1Target));
            if (func2 == null) return errorResult(functionQueries.buildFunctionTargetHint(func2Target));

            DecompInterface decompiler = new DecompInterface();
            try {
                decompiler.openProgram(session.program());
                TaskMonitor mon = session.monitor();

                DecompileResults res1 = decompiler.decompileFunction(func1, 30, mon);
                DecompileResults res2 = decompiler.decompileFunction(func2, 30, mon);

                if (!res1.decompileCompleted()) return errorResult("Failed to decompile " + func1Target);
                if (!res2.decompileCompleted()) return errorResult("Failed to decompile " + func2Target);

                String code1 = res1.getDecompiledFunction().getC();
                String code2 = res2.getDecompiledFunction().getC();

                String[] lines1 = code1.split("\n");
                String[] lines2 = code2.split("\n");

                JsonArray diffLines = new JsonArray();
                int maxLines = Math.max(lines1.length, lines2.length);
                for (int i = 0; i < maxLines; i++) {
                    String l1 = i < lines1.length ? lines1[i] : "";
                    String l2 = i < lines2.length ? lines2[i] : "";
                    if (!l1.equals(l2)) {
                        JsonObject diff = new JsonObject();
                        diff.addProperty("line", i + 1);
                        diff.addProperty("func1", l1);
                        diff.addProperty("func2", l2);
                        diff.addProperty("status", "changed");
                        diffLines.add(diff);
                    }
                }

                JsonObject f1Info = new JsonObject();
                f1Info.addProperty("name", func1.getName());
                f1Info.addProperty("lines", lines1.length);
                f1Info.addProperty("code", code1);

                JsonObject f2Info = new JsonObject();
                f2Info.addProperty("name", func2.getName());
                f2Info.addProperty("lines", lines2.length);
                f2Info.addProperty("code", code2);

                JsonObject result = new JsonObject();
                result.add("func1", f1Info);
                result.add("func2", f2Info);
                result.add("differences", diffLines);
                result.addProperty("diff_count", diffLines.size());
                return result;
            } finally {
                decompiler.dispose();
            }
        } catch (Exception e) {
            return errorResult("Failed to diff functions: " + e.getMessage());
        }
    }
}
