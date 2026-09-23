package ghidracli.analysis;

import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.JumpTable;
import ghidra.util.exception.CancelledException;
import ghidracli.function.FunctionQueries;
import ghidracli.function.FunctionVariables;
import ghidracli.query.AddressCodec;
import ghidracli.session.ProgramSession;
import java.util.Iterator;

import static ghidracli.protocol.JsonProtocol.errorResult;
import static ghidracli.protocol.JsonProtocol.getArgBool;
import static ghidracli.protocol.JsonProtocol.getArgString;
import static ghidracli.protocol.JsonProtocol.getDecompileTimeoutArg;

public final class DecompileCommands {
    private final ProgramSession session;
    private final FunctionQueries functionQueries;

    public DecompileCommands(ProgramSession session, FunctionQueries functionQueries) {
        this.session = session;
        this.functionQueries = functionQueries;
    }

    public JsonObject handleDecompile(JsonObject args) throws Exception {
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

        DecompileResults results = session.decompile(func, timeoutSecs);

        if (results.decompileCompleted()) {
            String code = results.getDecompiledFunction().getC();
            JsonObject result = functionQueries.functionContext(func);
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
            if (getArgBool(args, "with_addresses", false)) {
                result.add("line_addresses", DecompileAddresses.collect(results, session));
            }
            result.add("warnings", DecompileWarnings.collect(results));
            HighFunction highFunc = results.getHighFunction();
            if (highFunc == null) {
                result.add("basic_block_count", JsonNull.INSTANCE);
            } else {
                result.addProperty("basic_block_count", highFunc.getBasicBlocks().size());
            }

            if (getArgBool(args, "with_jump_tables", false)) {
                result.add("jump_tables", highFunc == null ? JsonNull.INSTANCE : jumpTables(highFunc));
            }

            boolean withVars = getArgBool(args, "with_vars", false);
            boolean withParams = getArgBool(args, "with_params", false);

            if (withVars || withParams) {
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
                            session.monitor().checkCancelled();
                            ghidra.program.model.pcode.HighSymbol sym = symIter2.next();
                            if (FunctionVariables.isVariable(sym) && !sym.isParameter()) {
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
            JsonObject error = errorResult(prefix + " for " + func.getName() + " at " +
                AddressCodec.format(func.getEntryPoint()) + ": " + detail.trim());
            error.add("detail", functionQueries.functionContext(func));
            return error;
        }
    }

    private JsonArray jumpTables(HighFunction highFunction) throws CancelledException {
        JsonArray tables = new JsonArray();
        for (JumpTable table : highFunction.getJumpTables()) {
            session.monitor().checkCancelled();
            JsonObject entry = new JsonObject();
            entry.addProperty("switch_address", AddressCodec.format(table.getSwitchAddress()));
            Address[] destinations = table.getCases();
            Integer[] labels = table.getLabelValues();
            JsonArray cases = new JsonArray();
            for (int i = 0; i < destinations.length; i++) {
                session.monitor().checkCancelled();
                JsonObject target = new JsonObject();
                target.addProperty("address", AddressCodec.format(destinations[i]));
                Integer label = i < labels.length ? labels[i] : null;
                target.addProperty("label", label);
                // Match DecompilerSwitchAnalysisCmd: the sentinel or the first
                // destination beyond the labels denotes the default guard case.
                target.addProperty("is_default", i == labels.length
                    || (label != null && label == 0xbad1abe1));
                cases.add(target);
            }
            entry.add("cases", cases);
            tables.add(entry);
        }
        return tables;
    }
}
