package ghidracli;

import com.google.gson.JsonObject;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import static ghidracli.JsonProtocol.errorResult;
import static ghidracli.JsonProtocol.getArgBool;
import static ghidracli.JsonProtocol.getArgString;
import static ghidracli.JsonProtocol.getDecompileTimeoutArg;

final class FunctionSignatureCommands {
    private static final Pattern C_TYPE_QUALIFIER =
        Pattern.compile("\\b(?:const|volatile|restrict|_Atomic)\\b");
    private static final Pattern ADJACENT_POINTER_RETURN_NAME =
        Pattern.compile("^([^()]*\\*)([A-Za-z_][A-Za-z_0-9]*\\s*\\()");

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
                sigParser.parse(func.getSignature(), prepareSignature(sigStr));

            if (funcDef == null) {
                return errorResult("Failed to parse signature: " + sigStr);
            }

            ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(
                func.getEntryPoint(), funcDef, SourceType.USER_DEFINED);
            if (!cmd.applyTo(session.program(), session.monitor())) {
                String diagnostic = cmd.getStatusMsg();
                throw new IllegalStateException(diagnostic == null || diagnostic.isBlank()
                    ? "Ghidra rejected the function signature" : diagnostic);
            }

            String newSig = null;
            try { newSig = func.getPrototypeString(false, false); } catch (Exception e) {}

            JsonObject result = new JsonObject();
            result.addProperty("status", "signature_set");
            result.addProperty("function", func.getName());
            result.addProperty("address", AddressCodec.format(func.getEntryPoint()));
            if (newSig != null) {
                result.addProperty("signature", newSig);
            }
            return result;
        } catch (Exception e) {
            return errorResult("Failed to set signature: " + e.getMessage());
        }
    }

    private static String prepareSignature(String signature) {
        // Ghidra's function datatypes cannot retain C type qualifiers. Check
        // before parsing: a trailing qualifier can otherwise become a parameter
        // name, and CParser accepts some qualifiers without storing them.
        Matcher qualifier = C_TYPE_QUALIFIER.matcher(signature);
        if (qualifier.find()) {
            throw new IllegalArgumentException("Ghidra function signatures cannot preserve the C type qualifier '"
                + qualifier.group() + "' at character " + (qualifier.start() + 1));
        }

        // FunctionSignatureParser splits the return type and function name on
        // whitespace. Insert only the missing separator in e.g. Entry **lookup;
        // retain the type spelling, pointer depth, and remaining declaration.
        return ADJACENT_POINTER_RETURN_NAME.matcher(signature).replaceFirst("$1 $2");
    }

    JsonObject handleFunctionSetReturnType(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");
        String target = getArgString(args, "target");
        String returnTypeName = getArgString(args, "return_type");
        if (target == null || returnTypeName == null)
            return errorResult("target and return_type required");
        int timeoutSecs = getDecompileTimeoutArg(args);

        try {
            Function func = functionQueries.findFunctionByNameOrAddress(target);
            if (func == null) return errorResult(functionQueries.buildFunctionTargetHint(target));

            DataType returnType = typeResolver.resolveDataType(returnTypeName);
            if (returnType == null)
                return errorResult("Return type not found: " + returnTypeName);

            Function effective = func.isThunk() ? func.getThunkedFunction(true) : func;
            int committed = new FunctionReturnType(session).set(effective, returnType, timeoutSecs);

            String sig = null;
            try { sig = func.getPrototypeString(false, false); } catch (Exception e) {}

            JsonObject result = new JsonObject();
            result.addProperty("status", "return_type_set");
            result.addProperty("function", func.getName());
            result.addProperty("address", AddressCodec.format(func.getEntryPoint()));
            result.addProperty("return_type", returnTypeName);
            result.addProperty("parameters_committed", committed);
            if (sig != null) result.addProperty("signature", sig);
            if (!effective.equals(func)) {
                result.addProperty("effective_function", effective.getName());
                result.addProperty("effective_address", AddressCodec.format(effective.getEntryPoint()));
            }
            return result;
        } catch (Exception e) {
            return errorResult("Failed to set return type: " + e.getMessage(), e);
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

            FunctionReturnType.requireCallingConvention(session.program(), convention);
            Function effective = func.isThunk() ? func.getThunkedFunction(true) : func;
            effective.setCallingConvention(convention);

            String sig = null;
            try { sig = func.getPrototypeString(false, false); } catch (Exception e) {}

            JsonObject result = new JsonObject();
            result.addProperty("status", "calling_convention_set");
            result.addProperty("function", func.getName());
            result.addProperty("address", AddressCodec.format(func.getEntryPoint()));
            result.addProperty("calling_convention", convention);
            if (sig != null) result.addProperty("signature", sig);
            if (!effective.equals(func)) {
                result.addProperty("effective_function", effective.getName());
                result.addProperty("effective_address", AddressCodec.format(effective.getEntryPoint()));
            }
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

            func.setNoReturn(value);

            JsonObject result = new JsonObject();
            result.addProperty("status", "noreturn_set");
            result.addProperty("function", func.getName());
            result.addProperty("address", AddressCodec.format(func.getEntryPoint()));
            result.addProperty("no_return", func.hasNoReturn());
            return result;
        } catch (Exception e) {
            return errorResult("Failed to set no-return: " + e.getMessage());
        }
    }

    JsonObject handleFunctionSetStackPurge(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");
        String target = getArgString(args, "target");
        if (target == null || target.isBlank()) return errorResult("target required");

        try {
            boolean unknown = false;
            if (args.has("unknown") && !args.get("unknown").isJsonNull()) {
                var value = args.get("unknown");
                if (!value.isJsonPrimitive() || !value.getAsJsonPrimitive().isBoolean()) {
                    return errorResult("unknown must be a boolean");
                }
                unknown = value.getAsBoolean();
            }
            boolean hasBytes = args.has("bytes") && !args.get("bytes").isJsonNull();
            if (hasBytes == unknown) return errorResult("Exactly one of bytes or unknown=true is required");
            int bytes = unknown ? Function.UNKNOWN_STACK_DEPTH_CHANGE : stackPurgeBytes(args);

            Function func = functionQueries.findFunctionByNameOrAddress(target);
            if (func == null) return errorResult(functionQueries.buildFunctionTargetHint(target));
            // Ghidra stores a thunk's signature metadata on its ultimate target.
            Function effective = func.isThunk() ? func.getThunkedFunction(true) : func;
            effective.setStackPurgeSize(bytes);

            JsonObject result = new JsonObject();
            result.addProperty("status", "stack_purge_set");
            result.addProperty("function", func.getName());
            result.addProperty("address", AddressCodec.format(func.getEntryPoint()));
            result.add("stack_purge", functionQueries.stackPurgeToJson(func));
            if (!effective.equals(func)) {
                result.addProperty("effective_function", effective.getName());
                result.addProperty("effective_address", AddressCodec.format(effective.getEntryPoint()));
            }
            return result;
        } catch (Exception e) {
            return errorResult("Failed to set stack purge: " + e.getMessage(), e);
        }
    }

    private static int stackPurgeBytes(JsonObject args) {
        var value = args.get("bytes");
        try {
            if (value.isJsonPrimitive() && value.getAsJsonPrimitive().isNumber()) {
                int bytes = value.getAsBigDecimal().intValueExact();
                // FunctionDB considers values above this range invalid; its
                // unknown/invalid sentinels must never be accepted as byte counts.
                if (bytes <= 0xffffff) return bytes;
            }
        } catch (ArithmeticException | NumberFormatException e) {
            // Reject fractions and overflow instead of narrowing them before mutation.
        }
        throw new IllegalArgumentException("bytes must be an integer from "
            + Integer.MIN_VALUE + " to " + 0xffffff);
    }

}
