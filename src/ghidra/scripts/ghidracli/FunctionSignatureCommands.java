package ghidracli;

import com.google.gson.JsonObject;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import java.util.Iterator;
import static ghidracli.JsonProtocol.errorResult;
import static ghidracli.JsonProtocol.getArgBool;
import static ghidracli.JsonProtocol.getArgString;

final class FunctionSignatureCommands {
    private final ProgramSession session;
    private final FunctionQueries functionQueries;
    private final TypeResolver typeResolver;

    FunctionSignatureCommands(ProgramSession session, FunctionQueries functionQueries, TypeResolver typeResolver) {
        this.session = session;
        this.functionQueries = functionQueries;
        this.typeResolver = typeResolver;
    }

    JsonObject handleFunctionSetSignature(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");
        String target = getArgString(args, "target");
        String sigStr = getArgString(args, "signature");
        if (target == null || sigStr == null) return errorResult("target and signature required");

        try {
            Function func = functionQueries.findFunctionByNameOrAddress(target);
            if (func == null) return errorResult(functionQueries.buildFunctionTargetHint(target));

            // Parse the signature using Ghidra's headless-friendly signature parser.
            // FunctionSignatureParser works without a PluginTool/ServiceProvider
            // (the DataTypeQueryService arg may be null), so it is safe in headless.
            ghidra.app.util.parser.FunctionSignatureParser sigParser =
                new ghidra.app.util.parser.FunctionSignatureParser(
                    session.program().getDataTypeManager(), null);
            ghidra.program.model.data.FunctionDefinitionDataType funcDef =
                sigParser.parse(func.getSignature(), sigStr);

            if (funcDef == null) {
                return errorResult("Failed to parse signature: " + sigStr);
            }

            ProgramTransaction transaction = session.transaction("Set function signature");
            try {
                ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(
                    func.getEntryPoint(), funcDef, SourceType.USER_DEFINED);
                cmd.applyTo(session.program());
                transaction.end(true);
            } catch (Exception e) {
                transaction.end(false);
                throw e;
            }

            String newSig = null;
            try { newSig = func.getPrototypeString(false, false); } catch (Exception e) {}

            JsonObject result = new JsonObject();
            result.addProperty("status", "signature_set");
            result.addProperty("function", func.getName());
            result.addProperty("address", func.getEntryPoint().toString());
            if (newSig != null) {
                result.addProperty("signature", newSig);
            }
            return result;
        } catch (Exception e) {
            return errorResult("Failed to set signature: " + e.getMessage());
        }
    }

    JsonObject handleFunctionSetReturnType(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");
        String target = getArgString(args, "target");
        String returnTypeName = getArgString(args, "return_type");
        if (target == null || returnTypeName == null)
            return errorResult("target and return_type required");

        try {
            Function func = functionQueries.findFunctionByNameOrAddress(target);
            if (func == null) return errorResult(functionQueries.buildFunctionTargetHint(target));

            DataType returnType = typeResolver.resolveDataType(returnTypeName);
            if (returnType == null)
                return errorResult("Return type not found: " + returnTypeName);

            ProgramTransaction transaction = session.transaction("Set return type");
            try {
                func.setReturnType(returnType, SourceType.USER_DEFINED);
                transaction.end(true);
            } catch (Exception e) {
                transaction.end(false);
                throw e;
            }

            String sig = null;
            try { sig = func.getPrototypeString(false, false); } catch (Exception e) {}

            JsonObject result = new JsonObject();
            result.addProperty("status", "return_type_set");
            result.addProperty("function", func.getName());
            result.addProperty("return_type", returnTypeName);
            if (sig != null) result.addProperty("signature", sig);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to set return type: " + e.getMessage());
        }
    }

    JsonObject handleFunctionSetCallingConvention(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");
        String target = getArgString(args, "target");
        String convention = getArgString(args, "convention");
        if (target == null || convention == null)
            return errorResult("target and convention required");

        try {
            Function func = functionQueries.findFunctionByNameOrAddress(target);
            if (func == null) return errorResult(functionQueries.buildFunctionTargetHint(target));

            ProgramTransaction transaction = session.transaction("Set calling convention");
            try {
                func.setCallingConvention(convention);
                transaction.end(true);
            } catch (Exception e) {
                transaction.end(true);
                throw e;
            }

            String sig = null;
            try { sig = func.getPrototypeString(false, false); } catch (Exception e) {}

            JsonObject result = new JsonObject();
            result.addProperty("status", "calling_convention_set");
            result.addProperty("function", func.getName());
            result.addProperty("calling_convention", convention);
            if (sig != null) result.addProperty("signature", sig);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to set calling convention: " + e.getMessage());
        }
    }

    JsonObject handleFunctionSetNoReturn(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");
        String target = getArgString(args, "target");
        boolean value = getArgBool(args, "value", true);
        if (target == null || target.isEmpty()) return errorResult("target required");

        try {
            Function func = functionQueries.findFunctionByNameOrAddress(target);
            if (func == null) return errorResult(functionQueries.buildFunctionTargetHint(target));

            ProgramTransaction transaction = session.transaction("Set no-return");
            try {
                func.setNoReturn(value);
                transaction.end(true);
            } catch (Exception e) {
                transaction.end(true);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "noreturn_set");
            result.addProperty("function", func.getName());
            result.addProperty("address", func.getEntryPoint().toString());
            result.addProperty("no_return", func.hasNoReturn());
            return result;
        } catch (Exception e) {
            return errorResult("Failed to set no-return: " + e.getMessage());
        }
    }

    JsonObject handleSetVarType(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");
        String funcTarget = getArgString(args, "function");
        String varName = getArgString(args, "var_name");
        String typeName = getArgString(args, "type_name");
        if (funcTarget == null || funcTarget.isEmpty()) return errorResult("Function target required");
        if (varName == null || varName.isEmpty()) return errorResult("Variable name required (--var)");
        if (typeName == null || typeName.isEmpty()) return errorResult("Type name required (--type)");

        try {
            Function func = functionQueries.findFunctionByNameOrAddress(funcTarget);
            if (func == null) return errorResult(functionQueries.buildFunctionTargetHint(funcTarget));

            DataType newType = typeResolver.resolveDataType(typeName);
            if (newType == null) return errorResult("Type not found: " + typeName);

            DecompInterface decompiler = new DecompInterface();
            try {
                decompiler.openProgram(session.program());
                TaskMonitor mon = session.monitor();
                DecompileResults results = decompiler.decompileFunction(func, 30, mon);
                if (!results.decompileCompleted())
                    return errorResult("Decompilation failed for " + funcTarget);

                ghidra.program.model.pcode.HighFunction highFunc = results.getHighFunction();
                if (highFunc == null)
                    return errorResult("Could not get high-level function representation");

                ghidra.program.model.pcode.LocalSymbolMap lsm = highFunc.getLocalSymbolMap();
                ghidra.program.model.pcode.HighSymbol targetSym = null;
                Iterator<ghidra.program.model.pcode.HighSymbol> symIter = lsm.getSymbols();
                while (symIter.hasNext()) {
                    ghidra.program.model.pcode.HighSymbol sym = symIter.next();
                    if (sym.getName().equals(varName)) {
                        targetSym = sym;
                        break;
                    }
                }

                if (targetSym == null)
                    return errorResult("Variable not found: " + varName + " in function " + func.getName());

                ProgramTransaction transaction = session.transaction("Set variable type");
                try {
                    HighFunctionDBUtil.updateDBVariable(targetSym, targetSym.getName(), newType, SourceType.USER_DEFINED);
                    transaction.end(true);
                } catch (Exception e) {
                    transaction.end(true);
                    throw e;
                }

                JsonObject result = new JsonObject();
                result.addProperty("status", "updated");
                result.addProperty("function", func.getName());
                result.addProperty("variable", varName);
                result.addProperty("new_type", newType.getName());
                result.addProperty("address", func.getEntryPoint().toString());
                return result;
            } finally {
                decompiler.dispose();
            }
        } catch (Exception e) {
            return errorResult("Failed to set variable type: " + e.getMessage());
        }
    }
}
