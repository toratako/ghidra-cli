package ghidracli.function;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.listing.VariableUtilities;
import ghidra.program.model.symbol.SourceType;
import ghidracli.query.AddressCodec;
import ghidracli.session.ProgramSession;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/** Prepare a complete ABI from a saved signature or a C declaration, then apply it once. */
final class FunctionStorage {
    private final ProgramSession session;
    private final FunctionQueries queries;

    FunctionStorage(ProgramSession session, FunctionQueries queries) {
        this.session = session;
        this.queries = queries;
    }

    JsonObject apply(Function function, JsonObject storage, FunctionDefinition definition) throws Exception {
        if (function.isThunk()) {
            Function owner = function.getThunkedFunction(true);
            throw new IllegalArgumentException("Select the storage owner directly: " + AddressCodec.format(owner.getEntryPoint())
                + " (" + owner.getName() + "); storage edits do not follow thunks");
        }
        VariableStorageCodec.keys(storage, Set.of("parameters", "return"));
        Map<String, JsonArray> locations = new LinkedHashMap<>();
        if (storage.has("parameters")) {
            for (JsonElement element : storage.getAsJsonArray("parameters")) {
                session.monitor().checkCancelled();
                JsonObject parameter = element.getAsJsonObject();
                VariableStorageCodec.keys(parameter, Set.of("name", "pieces"));
                String name = VariableStorageCodec.text(parameter, "name");
                if (!parameter.has("pieces") || !parameter.get("pieces").isJsonArray()) {
                    throw new IllegalArgumentException("Parameter storage requires a pieces array");
                }
                if (locations.putIfAbsent(name, parameter.getAsJsonArray("pieces")) != null) {
                    throw new IllegalArgumentException("Duplicate parameter storage: " + name);
                }
            }
        }
        if (locations.isEmpty() && !storage.has("return")) {
            throw new IllegalArgumentException("Specify at least one parameter or return storage location");
        }

        JsonObject before = state(function);
        Parameter[] saved = function.getParameters();
        if (definition == null && (function.getReturn().isForcedIndirect()
                || Arrays.stream(saved).anyMatch(Parameter::isForcedIndirect))) {
            throw new IllegalArgumentException("This ABI has forced-indirect values; use function set-signature with an explicit physical signature and all storage locations to avoid silently changing formal types");
        }
        List<Parameter> parameters = new ArrayList<>();
        if (definition == null) {
            for (Parameter old : saved) {
                session.monitor().checkCancelled();
                JsonArray requested = locations.remove(old.getName());
                DataType type = local(old.getDataType());
                VariableStorage location = requested == null ? preserve(old)
                    : VariableStorageCodec.decode(session.program(), type, requested, session.monitor());
                ParameterImpl parameter = new ParameterImpl(old.getName(), type, location,
                    session.program(), requested == null ? old.getSource() : SourceType.USER_DEFINED);
                requireExactStorage(parameter, type, location);
                parameter.setComment(old.getComment());
                parameters.add(parameter);
            }
        } else {
            for (var argument : definition.getArguments()) {
                session.monitor().checkCancelled();
                String name = argument.getName();
                if (name == null || name.isBlank()) throw new IllegalArgumentException("Custom signatures require named parameters");
                JsonArray requested = locations.remove(name);
                if (requested == null) throw new IllegalArgumentException("Missing storage for parameter " + name + "; custom signatures require all parameter and non-void return locations");
                DataType type = local(argument.getDataType());
                VariableStorage location = VariableStorageCodec.decode(session.program(), type, requested, session.monitor());
                ParameterImpl parameter = new ParameterImpl(name, type, location,
                    session.program(), SourceType.USER_DEFINED);
                requireExactStorage(parameter, type, location);
                for (Parameter old : saved) if (old.getName().equals(name)) parameter.setComment(old.getComment());
                parameters.add(parameter);
            }
        }
        if (!locations.isEmpty()) {
            List<String> names = parameters.stream().map(Parameter::getName).toList();
            throw new IllegalArgumentException("Unknown parameter storage target(s): " + locations.keySet()
                + "; available parameters: " + names + ". Inspect function get --with-signature; use function set-signature to define additional parameters");
        }
        DataType returnType = local(definition == null ? function.getReturnType() : definition.getReturnType());
        VariableStorage returnLocation;
        if (storage.has("return")) {
            returnLocation = VariableStorageCodec.decode(session.program(), returnType,
                storage.getAsJsonArray("return"), session.monitor());
        } else if (VoidDataType.isVoidDataType(returnType)) {
            returnLocation = VariableStorage.VOID_STORAGE;
        } else if (definition == null) {
            returnLocation = preserve(function.getReturn());
        } else {
            throw new IllegalArgumentException("Missing return storage; custom signatures require all non-void return and parameter locations");
        }
        ReturnParameterImpl result = new ReturnParameterImpl(returnType, returnLocation, session.program());
        requireExactStorage(result, returnType, returnLocation);
        for (int i = 0; i < parameters.size(); i++) {
            session.monitor().checkCancelled();
            Parameter parameter = parameters.get(i);
            for (int j = 0; j < i; j++) {
                Parameter other = parameters.get(j);
                if (other.getName().equals(parameter.getName())) throw new IllegalArgumentException("Duplicate parameter name: " + parameter.getName());
                if (other.getVariableStorage().intersects(parameter.getVariableStorage())) {
                    throw new IllegalArgumentException("Parameter storage overlaps: " + other.getName() + " and " + parameter.getName());
                }
            }
            VariableUtilities.checkVariableConflict(Arrays.asList(function.getLocalVariables()),
                parameter, parameter.getVariableStorage(), null);
        }
        String convention = definition == null ? null : definition.getCallingConventionName();
        if (Function.UNKNOWN_CALLING_CONVENTION_STRING.equals(convention)
                || Function.DEFAULT_CALLING_CONVENTION_STRING.equals(convention)) convention = null;
        if (convention != null) FunctionReturnType.requireCallingConvention(session.program(), convention);
        String expectedConvention = convention == null ? function.getCallingConventionName() : convention;
        boolean variadic = definition == null ? function.hasVarArgs() : definition.hasVarArgs();
        session.monitor().checkCancelled();
        function.updateFunction(convention, result, parameters, Function.FunctionUpdateType.CUSTOM_STORAGE,
            false, SourceType.USER_DEFINED);
        if (definition != null) {
            function.setVarArgs(variadic);
            if (!function.getName().equals(definition.getName())) function.setName(definition.getName(), SourceType.USER_DEFINED);
        }
        session.monitor().checkCancelled();
        Parameter[] actual = function.getParameters();
        if (!function.hasCustomVariableStorage() || actual.length != parameters.size()
                || !Objects.equals(expectedConvention, function.getCallingConventionName())
                || function.hasVarArgs() != variadic || !sameValue(function.getReturn(), result)) {
            throw new IllegalStateException("Ghidra did not retain the requested signature and return storage");
        }
        for (int i = 0; i < actual.length; i++) {
            Parameter expected = parameters.get(i);
            if (!actual[i].getName().equals(expected.getName()) || !sameValue(actual[i], expected)
                    || !Objects.equals(actual[i].getComment(), expected.getComment()) || actual[i].isAutoParameter()) {
                throw new IllegalStateException("Ghidra did not retain parameter " + expected.getName());
            }
        }
        JsonObject after = state(function);
        JsonObject receipt = new JsonObject();
        receipt.addProperty("status", definition == null ? "storage_set" : "signature_set");
        receipt.addProperty("function", function.getName());
        receipt.addProperty("address", AddressCodec.format(function.getEntryPoint()));
        receipt.addProperty("signature", function.getPrototypeString(false, false));
        receipt.addProperty("changed", !before.equals(after));
        receipt.add("before", before);
        receipt.add("after", after);
        return receipt;
    }

    private JsonObject state(Function function) throws Exception {
        JsonObject state = queries.signatureDetailsToJson(function);
        state.addProperty("name", function.getName());
        state.addProperty("signature", function.getPrototypeString(false, false));
        state.addProperty("calling_convention", function.getCallingConventionName());
        return state;
    }

    private DataType local(DataType type) {
        DataType localized = type.clone(session.program().getDataTypeManager());
        if (!VoidDataType.isVoidDataType(localized) && localized.getLength() <= 0) {
            throw new IllegalArgumentException("Storage requires fixed-length types");
        }
        return localized;
    }

    private VariableStorage preserve(Parameter parameter) throws Exception {
        VariableStorage storage = parameter.getVariableStorage();
        if (!storage.isValid()) throw new IllegalArgumentException("Unassigned or invalid storage for " + parameter.getName()
            + "; specify its location before freezing the signature");
        if (storage.isVoidStorage()) return VariableStorage.VOID_STORAGE;
        // Copy locations only: custom storage materializes automatic parameters.
        return new VariableStorage(session.program(), storage.getVarnodes());
    }

    private static boolean sameValue(Parameter actual, Parameter expected) {
        return actual.getDataType().isEquivalent(expected.getDataType())
            && actual.getVariableStorage().equals(expected.getVariableStorage());
    }

    private static void requireExactStorage(Parameter parameter, DataType type, VariableStorage location) {
        if (!parameter.getDataType().isEquivalent(type) || !parameter.getVariableStorage().equals(location)) {
            throw new IllegalArgumentException("Ghidra cannot retain the exact storage " + location
                + " for type " + type.getPathName());
        }
    }
}
