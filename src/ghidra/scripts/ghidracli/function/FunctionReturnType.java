package ghidracli.function;

import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.listing.VariableUtilities;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidracli.session.ProgramSession;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** Preserve uncommitted inputs before a return edit locks the function signature. */
final class FunctionReturnType {
    private final ProgramSession session;

    FunctionReturnType(ProgramSession session) {
        this.session = session;
    }

    int set(Function function, DataType returnType, int timeoutSecs) throws Exception {
        if (Undefined.isUndefined(returnType) || function.isExternal()
                || function.getSignatureSource() != SourceType.DEFAULT) {
            function.setReturnType(returnType, SourceType.USER_DEFINED);
            return 0;
        }
        if (session.program().getListing().getInstructionAt(function.getEntryPoint()) == null) {
            throw cannotPreserve("No instruction at the function entry point");
        }

        DecompileResults results = session.decompile(function, timeoutSecs);
        if (!results.decompileCompleted()) {
            String reason = results.isTimedOut() ? "Decompilation timed out" : "Decompilation failed";
            throw cannotPreserve(reason + ": " + results.getErrorMessage());
        }
        HighFunction high = results.getHighFunction();
        if (high == null) throw cannotPreserve("Decompiler returned no high-level function");
        LocalSymbolMap symbols = high.getLocalSymbolMap();
        Parameter[] existing = function.getParameters();
        PrototypeModel convention = conventionForCommit(function, high);
        if (parametersMatch(symbols, existing)) {
            if (!convention.getName().equals(function.getCallingConventionName())) {
                function.setCallingConvention(convention.getName());
            }
            function.setReturnType(returnType, SourceType.USER_DEFINED);
            return 0;
        }

        List<Parameter> parameters = new ArrayList<>();
        List<Boolean> inferred = new ArrayList<>();
        boolean[] retained = new boolean[existing.length];
        int committed = 0;
        for (int i = 0; i < symbols.getNumParams(); i++) {
            session.monitor().checkCancelled();
            HighSymbol symbol = symbols.getParamSymbol(i);
            if (symbol == null || symbol.getCategoryIndex() != i || !symbol.getStorage().isValid()) {
                throw cannotPreserve("Decompiler returned an invalid parameter layout");
            }
            Parameter previous = null;
            for (int j = 0; j < existing.length; j++) {
                if (!retained[j] && symbol.getStorage().compareTo(existing[j].getVariableStorage()) == 0) {
                    previous = existing[j];
                    retained[j] = true;
                    break;
                }
            }
            Parameter parameter;
            if (previous == null) {
                DataType type = function.hasCustomVariableStorage()
                    ? Undefined.getUndefinedDataType(symbol.getSize()) : symbol.getDataType();
                parameter = new ParameterImpl(symbol.getName(), type, symbol.getStorage(),
                    session.program(), SourceType.ANALYSIS);
                committed++;
            } else {
                // Keep dynamic auto/indirect flags and the formal type; the native
                // copy constructor strips those flags and does not copy comments.
                parameter = new ParameterImpl(previous.getName(), previous.getOrdinal(),
                    previous.getFormalDataType(), previous.getVariableStorage(), false,
                    session.program(), previous.getSource());
                parameter.setComment(previous.getComment());
            }
            for (Symbol named : session.program().getSymbolTable().getSymbols(parameter.getName(), function)) {
                if (previous == null || !named.equals(previous.getSymbol())) {
                    throw cannotPreserve("Parameter name conflicts with another symbol: " + parameter.getName());
                }
            }
            parameters.add(parameter);
            inferred.add(previous == null);
        }
        for (int i = 0; i < existing.length; i++) {
            if (!retained[i]) {
                throw cannotPreserve("Decompiler omitted or moved existing parameter: " + existing[i].getName());
            }
        }

        boolean custom = function.hasCustomVariableStorage();
        if (!custom) {
            if (!dynamicStorageMatches(function, convention, parameters)) {
                throw cannotPreserve("Inferred parameters do not match the calling convention's storage");
            }
            // Leave types open to inference wherever their size alone preserves
            // the ABI. Float/aggregate types may be needed to select the right registers.
            for (int i = 0; i < parameters.size(); i++) {
                if (!inferred.get(i) || parameters.get(i).isAutoParameter()) continue;
                session.monitor().checkCancelled();
                Parameter typed = parameters.get(i);
                Parameter untyped = new ParameterImpl(typed.getName(),
                    Undefined.getUndefinedDataType(typed.getLength()), typed.getVariableStorage(),
                    session.program(), typed.getSource());
                parameters.set(i, untyped);
                if (!dynamicStorageMatches(function, convention, parameters)) parameters.set(i, typed);
            }
        }

        List<Parameter> formal = new ArrayList<>();
        for (Parameter parameter : parameters) {
            if (custom || !parameter.isAutoParameter()) formal.add(parameter);
            VariableUtilities.checkVariableConflict(Arrays.asList(function.getLocalVariables()),
                parameter, parameter.getVariableStorage(), null);
        }
        // Never force-remove conflicting locals or rename symbols, as the GUI
        // commit helper can do. The request boundary rolls back native failures.
        function.updateFunction(convention.getName(), null, formal,
            custom ? FunctionUpdateType.CUSTOM_STORAGE : FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
            false, SourceType.USER_DEFINED);
        if (!VariableUtilities.storageMatches(parameters, function.getParameters())) {
            throw cannotPreserve("Ghidra could not retain the inferred parameter storage");
        }
        function.setReturnType(returnType, SourceType.USER_DEFINED);
        return committed;
    }

    private static boolean parametersMatch(LocalSymbolMap symbols, Parameter[] parameters) {
        if (symbols.getNumParams() != parameters.length) return false;
        for (int i = 0; i < parameters.length; i++) {
            HighSymbol symbol = symbols.getParamSymbol(i);
            if (symbol == null || symbol.getCategoryIndex() != i
                    || symbol.getStorage().compareTo(parameters[i].getVariableStorage()) != 0) return false;
        }
        return true;
    }

    private boolean dynamicStorageMatches(Function function, PrototypeModel convention,
            List<Parameter> parameters) {
        List<DataType> types = new ArrayList<>();
        types.add(function.getReturn().getFormalDataType());
        for (Parameter parameter : parameters) {
            if (!parameter.isAutoParameter()) types.add(parameter.getFormalDataType());
        }
        VariableStorage[] storage = convention.getStorageLocations(session.program(),
            types.toArray(new DataType[0]), true);
        if (storage.length != parameters.size() + 1) return false;
        for (int i = 0; i < parameters.size(); i++) {
            if (storage[i + 1].compareTo(parameters.get(i).getVariableStorage()) != 0) return false;
        }
        return true;
    }

    private PrototypeModel conventionForCommit(Function function, HighFunction high) {
        String name = function.getCallingConventionName();
        if (name == null || Function.UNKNOWN_CALLING_CONVENTION_STRING.equals(name)) {
            name = high.getFunctionPrototype().getModelName();
        }
        // Ghidra may already store its native "default" sentinel. Resolve that
        // existing ABI even though the CLI setter only accepts concrete names.
        if (name == null || Function.UNKNOWN_CALLING_CONVENTION_STRING.equals(name)
                || Function.DEFAULT_CALLING_CONVENTION_STRING.equals(name)) {
            PrototypeModel defaultModel = session.program().getCompilerSpec().getDefaultCallingConvention();
            if (defaultModel == null) throw cannotPreserve("Compiler specification has no default calling convention");
            name = defaultModel.getName();
        }
        return requireCallingConvention(session.program(), name);
    }

    static PrototypeModel requireCallingConvention(Program program, String name) {
        List<String> supported = new ArrayList<>();
        for (PrototypeModel model : program.getCompilerSpec().getCallingConventions()) {
            if (model.getName().equals(name)) return model;
            supported.add(model.getName());
        }
        throw new IllegalArgumentException("Unsupported calling convention: " + name
            + ". Supported calling conventions: " + String.join(", ", supported)
            + ". Use `program list-calling-conventions` to inspect this program's conventions.");
    }

    private static IllegalStateException cannotPreserve(String reason) {
        return new IllegalStateException(reason
            + "; cannot safely preserve inferred parameters. Use `function set-signature` with the full signature.");
    }
}
