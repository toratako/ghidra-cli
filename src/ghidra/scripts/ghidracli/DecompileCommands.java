package ghidracli;

import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.util.task.TaskMonitor;
import java.util.Iterator;
import static ghidracli.JsonProtocol.errorResult;
import static ghidracli.JsonProtocol.getArgBool;
import static ghidracli.JsonProtocol.getArgString;
import static ghidracli.JsonProtocol.getDecompileTimeoutArg;

final class DecompileCommands {
    private final ProgramSession session;
    private final FunctionQueries functionQueries;

    DecompileCommands(ProgramSession session, FunctionQueries functionQueries) {
        this.session = session;
        this.functionQueries = functionQueries;
    }

    JsonObject handleDecompile(JsonObject args) {
        if (session.program() == null) {
            return errorResult("No program loaded");
        }

        String addrStr = getArgString(args, "address");
        if (addrStr == null || addrStr.isEmpty()) {
            return errorResult("No address provided");
        }

        Function func = functionQueries.findFunctionByNameOrAddress(addrStr);
        if (func == null) {
            return errorResult(functionQueries.buildFunctionTargetHint(addrStr));
        }
        int timeoutSecs = getDecompileTimeoutArg(args);

        DecompInterface decompiler = new DecompInterface();
        decompiler.setOptions(new DecompileOptions());
        try {
            decompiler.openProgram(session.program());

            TaskMonitor mon = session.monitor();
            // Ghidra defines zero as no native decompiler timeout. Large but
            // valid functions can exceed the historical hard-coded 30 seconds,
            // so default to unbounded and let callers opt into a ceiling.
            DecompileResults results = decompiler.decompileFunction(func, timeoutSecs, mon);

            if (results.decompileCompleted()) {
                String code = results.getDecompiledFunction().getC();
                JsonObject result = new JsonObject();
                result.addProperty("name", func.getName());
                result.addProperty("address", AddressCodec.format(func.getEntryPoint()));
                String sig = null;
                try {
                    sig = func.getPrototypeString(false, false);
                } catch (Exception e) {
                    // ignore
                }
                if (sig != null) {
                    result.addProperty("signature", sig);
                } else {
                    result.add("signature", JsonNull.INSTANCE);
                }
                result.addProperty("code", code);

                boolean withVars = getArgBool(args, "with_vars", false);
                boolean withParams = getArgBool(args, "with_params", false);

                if (withVars || withParams) {
                    ghidra.program.model.pcode.HighFunction highFunc = results.getHighFunction();
                    if (highFunc != null) {
                        ghidra.program.model.pcode.LocalSymbolMap lsm = highFunc.getLocalSymbolMap();

                        if (withParams) {
                            JsonArray params = new JsonArray();
                            for (int i = 0; i < lsm.getNumParams(); i++) {
                                ghidra.program.model.pcode.HighSymbol sym = lsm.getParamSymbol(i);
                                JsonObject paramObj = new JsonObject();
                                paramObj.addProperty("name", sym.getName());
                                paramObj.addProperty("type", sym.getDataType().getName());
                                paramObj.addProperty("size", sym.getSize());
                                paramObj.addProperty("storage", sym.getStorage().toString());
                                params.add(paramObj);
                            }
                            result.add("params", params);
                        }

                        if (withVars) {
                            JsonArray vars = new JsonArray();
                            Iterator<ghidra.program.model.pcode.HighSymbol> symIter2 = lsm.getSymbols();
                            while (symIter2.hasNext()) {
                                ghidra.program.model.pcode.HighSymbol sym = symIter2.next();
                                if (!sym.isParameter()) {
                                    JsonObject varObj = new JsonObject();
                                    varObj.addProperty("name", sym.getName());
                                    varObj.addProperty("type", sym.getDataType().getName());
                                    varObj.addProperty("size", sym.getSize());
                                    varObj.addProperty("storage", sym.getStorage().toString());
                                    vars.add(varObj);
                                }
                            }
                            result.add("variables", vars);
                        }
                    }
                }

                return result;
            } else {
                String detail = results.getErrorMessage();
                if (detail == null || detail.trim().isEmpty()) {
                    detail = "no diagnostic returned by Ghidra";
                }
                String prefix;
                if (results.isTimedOut()) {
                    prefix = "Decompilation timed out" +
                        (timeoutSecs == 0 ? "" : " after " + timeoutSecs + " seconds");
                } else if (results.isCancelled()) {
                    prefix = "Decompilation cancelled";
                } else if (results.failedToStart()) {
                    prefix = "Decompiler failed to start";
                } else {
                    prefix = "Decompilation failed";
                }
                return errorResult(prefix + " for " + func.getName() + " at " +
                    AddressCodec.format(func.getEntryPoint()) + ": " + detail.trim());
            }
        } finally {
            decompiler.dispose();
        }
    }
}
