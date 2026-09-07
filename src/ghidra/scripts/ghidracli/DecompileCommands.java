package ghidracli;

import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.util.task.TaskMonitor;
import java.util.Iterator;
import static ghidracli.JsonProtocol.errorResult;
import static ghidracli.JsonProtocol.getArgBool;
import static ghidracli.JsonProtocol.getArgInt;
import static ghidracli.JsonProtocol.getArgString;

final class DecompileCommands {
    private final ProgramSession session;
    private final AddressResolver addressResolver;
    private final FunctionQueries functionQueries;

    DecompileCommands(ProgramSession session, AddressResolver addressResolver, FunctionQueries functionQueries) {
        this.session = session;
        this.addressResolver = addressResolver;
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

        Address addr = addressResolver.resolveAddress(addrStr);
        if (addr == null) {
            return errorResult(functionQueries.buildFunctionTargetHint(addrStr));
        }

        FunctionManager fm = session.program().getFunctionManager();
        Function func = fm.getFunctionContaining(addr);
        if (func == null) {
            return errorResult("No function at address " + addrStr);
        }

        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.openProgram(session.program());

            TaskMonitor mon = session.monitor();
            // Ghidra defines zero as no native decompiler timeout. Large but
            // valid functions can exceed the historical hard-coded 30 seconds,
            // so default to unbounded and let callers opt into a ceiling.
            int timeoutSecs = Math.max(0, getArgInt(args, "timeout_secs", 0));
            DecompileResults results = decompiler.decompileFunction(func, timeoutSecs, mon);

            if (results.decompileCompleted()) {
                String code = results.getDecompiledFunction().getC();
                JsonObject result = new JsonObject();
                result.addProperty("name", func.getName());
                result.addProperty("address", func.getEntryPoint().toString());
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
                            Iterator<ghidra.program.model.pcode.HighSymbol> symIter = lsm.getSymbols();
                            while (symIter.hasNext()) {
                                ghidra.program.model.pcode.HighSymbol sym = symIter.next();
                                if (sym.isParameter()) {
                                    JsonObject paramObj = new JsonObject();
                                    paramObj.addProperty("name", sym.getName());
                                    paramObj.addProperty("type", sym.getDataType().getName());
                                    paramObj.addProperty("size", sym.getSize());
                                    paramObj.addProperty("storage", sym.getStorage().toString());
                                    params.add(paramObj);
                                }
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
                    func.getEntryPoint() + ": " + detail.trim());
            }
        } finally {
            decompiler.dispose();
        }
    }
}
