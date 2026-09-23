package ghidracli.function;

import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.StackFrame;
import ghidra.program.model.listing.Variable;
import ghidracli.memory.MemoryBlockInfo;
import ghidracli.query.AddressCodec;
import ghidracli.query.AddressResolver;
import ghidracli.query.NameSuggestions;
import ghidracli.session.ProgramSession;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class FunctionQueries {
    private final ProgramSession session;
    private final AddressResolver addressResolver;

    public FunctionQueries(ProgramSession session, AddressResolver addressResolver) {
        this.session = session;
        this.addressResolver = addressResolver;
    }

    public JsonObject functionContext(Function func) {
        JsonObject funcData = new JsonObject();
        funcData.addProperty("name", func.getName());
        funcData.addProperty("address", AddressCodec.format(func.getEntryPoint()));
        funcData.addProperty("is_external", func.isExternal());
        var block = session.program().getMemory().getBlock(func.getEntryPoint());
        funcData.add("entry_memory", block == null ? JsonNull.INSTANCE : MemoryBlockInfo.summary(block));
        return funcData;
    }

    JsonObject functionToJson(Function func) {
        JsonObject funcData = functionContext(func);
        funcData.addProperty("size", func.getBody().getNumAddresses());
        funcData.addProperty("entry_point", AddressCodec.format(func.getEntryPoint()));
        funcData.add("tags", TagSupport.functionTagNames(func));

        String sig = null;
        try {
            sig = func.getPrototypeString(false, false);
        } catch (Exception e) {
            // ignore
        }
        if (sig != null) {
            funcData.addProperty("signature", sig);
        } else {
            funcData.add("signature", JsonNull.INSTANCE);
        }

        funcData.addProperty("calling_convention", func.getCallingConventionName());
        funcData.addProperty("no_return", func.hasNoReturn());
        funcData.add("stack_purge", stackPurgeToJson(func));

        String comment = func.getComment();
        if (comment != null) {
            funcData.addProperty("comment", comment);
        } else {
            funcData.add("comment", JsonNull.INSTANCE);
        }

        return funcData;
    }

    JsonObject stackPurgeToJson(Function func) {
        int bytes = func.getStackPurgeSize();
        JsonObject result = new JsonObject();
        if (bytes == Function.UNKNOWN_STACK_DEPTH_CHANGE) {
            result.addProperty("state", "unknown");
            result.add("bytes", JsonNull.INSTANCE);
        } else if (!func.isStackPurgeSizeValid()) {
            result.addProperty("state", "invalid");
            result.add("bytes", JsonNull.INSTANCE);
        } else {
            result.addProperty("state", "known");
            result.addProperty("bytes", bytes);
        }
        return result;
    }

    JsonObject functionDetailToJson(Function func) throws ghidra.util.exception.CancelledException {
        JsonObject result = functionToJson(func);
        JsonArray ranges = new JsonArray();
        for (var range : func.getBody().getAddressRanges()) {
            session.monitor().checkCancelled();
            JsonObject row = new JsonObject();
            row.addProperty("start", AddressCodec.format(range.getMinAddress()));
            row.addProperty("end", AddressCodec.format(range.getMaxAddress()));
            ranges.add(row);
        }
        result.add("body_ranges", ranges);
        return result;
    }

    public JsonObject signatureDetailsToJson(Function func) throws ghidra.util.exception.CancelledException {
        JsonObject result = new JsonObject();
        result.addProperty("storage_mode", func.hasCustomVariableStorage() ? "custom" : "dynamic");
        result.addProperty("source", func.getSignatureSource().name());
        result.addProperty("variadic", func.hasVarArgs());
        result.add("return", parameterTypeToJson(func.getReturn()));
        JsonArray params = new JsonArray();
        // Function APIs include convention-generated parameters in signature order.
        // Read through the selected function: thunks can specialize the 'this' type.
        for (Parameter param : func.getParameters()) {
            session.monitor().checkCancelled();
            JsonObject row = parameterTypeToJson(param);
            row.addProperty("ordinal", param.getOrdinal());
            row.addProperty("name", param.getName());
            row.addProperty("auto_parameter", param.getAutoParameterType() == null
                ? null : param.getAutoParameterType().name());
            params.add(row);
        }
        result.add("params", params);
        if (func.isThunk()) {
            Function immediate = func.getThunkedFunction(false);
            result.addProperty("thunk_function", immediate.getName());
            result.addProperty("thunk_address", AddressCodec.format(immediate.getEntryPoint()));
            Function effective = func.getThunkedFunction(true);
            result.addProperty("effective_function", effective.getName());
            result.addProperty("effective_address", AddressCodec.format(effective.getEntryPoint()));
        }
        return result;
    }

    JsonObject frameDetailsToJson(Function func) throws ghidra.util.exception.CancelledException {
        StackFrame frame = func.getStackFrame();
        // FunctionDB forwards the frame through the entire thunk chain. Keep its
        // owner explicit even when the caller did not request signature details.
        Function effective = frame.getFunction();
        JsonObject result = new JsonObject();
        result.addProperty("effective_function", effective.getName());
        result.addProperty("effective_address", AddressCodec.format(effective.getEntryPoint()));
        result.addProperty("frame_size", frame.getFrameSize());
        result.addProperty("local_size", frame.getLocalSize());
        result.addProperty("parameter_size", frame.getParameterSize());
        int parameterOffset = frame.getParameterOffset();
        result.add("parameter_offset", parameterOffset == StackFrame.UNKNOWN_PARAM_OFFSET
            ? JsonNull.INSTANCE : new com.google.gson.JsonPrimitive(parameterOffset));
        result.addProperty("return_address_offset", frame.getReturnAddressOffset());
        result.addProperty("grows_negative", frame.growsNegative());
        JsonArray variables = new JsonArray();
        for (Variable variable : frame.getStackVariables()) {
            session.monitor().checkCancelled();
            DataType type = variable.getDataType();
            JsonObject row = new JsonObject();
            row.addProperty("name", variable.getName());
            row.addProperty("kind", variable instanceof Parameter ? "parameter" : "local");
            row.addProperty("type", type.getName());
            row.addProperty("type_path", type.getPathName());
            row.addProperty("size", variable.getLength());
            row.addProperty("storage", variable.getVariableStorage().toString());
            // A compound variable can occupy both a register and the stack.
            // Report the stack component separately from the full storage size.
            var stack = variable.getFirstStorageVarnode();
            if (!stack.getAddress().isStackAddress()) stack = variable.getLastStorageVarnode();
            row.addProperty("stack_offset", variable.getVariableStorage().getStackOffset());
            row.addProperty("stack_size", stack.getSize());
            row.addProperty("source", variable.getSource().name());
            if (variable instanceof Parameter parameter) {
                row.addProperty("ordinal", parameter.getOrdinal());
                row.addProperty("auto_parameter", parameter.getAutoParameterType() == null
                    ? null : parameter.getAutoParameterType().name());
            } else {
                row.addProperty("first_use_offset", variable.getFirstUseOffset());
            }
            variables.add(row);
        }
        result.add("stack_variables", variables);
        return result;
    }

    private JsonObject parameterTypeToJson(Parameter param) {
        DataType type = param.getDataType();
        JsonObject result = new JsonObject();
        result.addProperty("type", type.getName());
        result.addProperty("type_path", type.getPathName());
        result.addProperty("size", type.getLength());
        // Preserve native <VOID>, <UNASSIGNED>, and <BAD> storage, not an empty location.
        result.addProperty("storage", param.getVariableStorage().toString());
        result.addProperty("forced_indirect", param.isForcedIndirect());
        if (param.isForcedIndirect()) {
            DataType formal = param.getFormalDataType();
            result.addProperty("formal_type", formal.getName());
            result.addProperty("formal_type_path", formal.getPathName());
        }
        return result;
    }

    public String buildFunctionTargetHint(String target) {
        if (session.program() == null || target == null || target.isEmpty()) {
            return "Function not found";
        }

        String query = target.toLowerCase();
        List<String> containsMatches = new ArrayList<>();
        List<String> fuzzyMatches = new ArrayList<>();
        FunctionIterator iter = session.program().getFunctionManager().getFunctions(true);

        while (iter.hasNext()) {
            Function func = iter.next();
            String name = func.getName();
            String lname = name.toLowerCase();

            if (lname.contains(query)) {
                containsMatches.add(name);
            } else if (query.length() >= 3 && NameSuggestions.levenshteinDistance(lname, query) <= 3) {
                fuzzyMatches.add(name);
            }
        }

        Collections.sort(containsMatches);
        Collections.sort(fuzzyMatches);

        List<String> suggestions = new ArrayList<>();
        for (String name : containsMatches) {
            suggestions.add(name);
            if (suggestions.size() >= 5) break;
        }
        if (suggestions.size() < 5) {
            for (String name : fuzzyMatches) {
                if (!suggestions.contains(name)) suggestions.add(name);
                if (suggestions.size() >= 5) break;
            }
        }

        StringBuilder hint = new StringBuilder();
        hint.append("Cannot resolve function target: ").append(target)
            .append(". Try: ghidra-cli function list --help");
        if (!suggestions.isEmpty()) {
            hint.append(". Closest matches: ").append(String.join(", ", suggestions));
        }
        return hint.toString();
    }

    public Function findFunctionByNameOrAddress(String nameOrAddr) {
        if (session.program() == null || nameOrAddr == null || nameOrAddr.isEmpty()) {
            return null;
        }

        FunctionManager fm = session.program().getFunctionManager();

        Address explicit = addressResolver.parseAddress(nameOrAddr);
        if (explicit != null) return fm.getFunctionContaining(explicit);

        Map<Address, Function> candidates = new LinkedHashMap<>();
        for (Address address : addressResolver.namedAddresses(nameOrAddr.trim())) {
            Function function = fm.getFunctionContaining(address);
            if (function != null) candidates.put(function.getEntryPoint(), function);
        }
        if (candidates.size() > 1) {
            throw new IllegalArgumentException("Ambiguous function target '" + nameOrAddr
                + "' at " + candidates.keySet().stream().map(AddressCodec::format).toList()
                + "; use a 0x-prefixed address");
        }
        return candidates.isEmpty() ? null : candidates.values().iterator().next();
    }
}
