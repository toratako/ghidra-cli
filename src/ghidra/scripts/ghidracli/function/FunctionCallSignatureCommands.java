package ghidracli.function;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.DataTypeSymbol;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.CancelledException;
import ghidracli.listing.InstructionFlow;
import ghidracli.query.AddressCodec;
import ghidracli.session.ProgramSession;

import static ghidracli.protocol.JsonProtocol.errorResult;
import static ghidracli.protocol.JsonProtocol.getArgString;

/** Saved prototype overrides owned by the selected caller, including stale sites. */
public final class FunctionCallSignatureCommands {
    private record Site(Function caller, Address address, Instruction instruction, int callCount,
            String callKind) {}
    private record Saved(Symbol symbol, DataTypeSymbol type) {
        FunctionSignature signature() {
            return type == null ? null : (FunctionSignature) type.getDataType();
        }
    }

    private final ProgramSession session;
    private final FunctionQueries functions;

    public FunctionCallSignatureCommands(ProgramSession session, FunctionQueries functions) {
        this.session = session;
        this.functions = functions;
    }

    public JsonObject handleGet(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");
        try {
            Site site = resolveSite(args);
            Saved saved = findSaved(site);
            if (saved != null && saved.type() == null) {
                throw new IllegalStateException("Saved call-site override has no readable prototype; "
                    + "use function call-signature clear to remove it");
            }
            JsonObject result = context(site);
            result.add("override", describe(saved));
            return result;
        } catch (Exception e) {
            return errorResult("Failed to get call-site signature: " + e.getMessage(), e);
        }
    }

    public JsonObject handleSet(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");
        try {
            Site site = resolveSite(args);
            if (!site.caller().getBody().contains(site.address())) {
                throw new IllegalArgumentException("Call-site address is outside the selected function body");
            }
            if (site.instruction() == null) {
                throw new IllegalArgumentException("Call-site address must be an exact instruction start");
            }
            if (site.callCount() != 1) {
                throw new IllegalArgumentException("Call-site instruction must have exactly one effective "
                    + "CALL or CALLIND operation; found " + site.callCount());
            }
            Saved previous = findSaved(site);
            FunctionDefinitionDataType definition = FunctionSignatureSupport.parse(session,
                previous == null ? null : previous.signature(), required(args, "signature"));
            String convention = getArgString(args, "convention");
            if (convention == null) {
                var model = session.program().getCompilerSpec().getDefaultCallingConvention();
                if (model == null) throw new IllegalArgumentException("Program has no default calling convention");
                convention = model.getName();
            } else {
                FunctionReturnType.requireCallingConvention(session.program(), convention);
            }
            definition.setCallingConvention(convention);
            // Prototype names are not callee identities. Use the same neutral
            // name as Ghidra's writer so equivalent sites share one datatype.
            definition.setName("tmpname");
            JsonElement before = describe(previous);
            JsonObject after = describeSignature(definition);
            boolean changed = previous == null || !before.equals(after);
            if (changed) {
                removeMarker(previous);
                Namespace space = HighFunction.findCreateOverrideSpace(site.caller());
                if (space == null) throw new IllegalStateException("Could not create override namespace");
                // Native writeOverride uses clearold=true, whose marker cleanup
                // is not confined to this caller. Delete only our exact marker
                // and retain all other namespaces at this instruction address.
                DataTypeSymbol replacement =
                    new DataTypeSymbol(definition, "prt", HighFunctionDBUtil.AUTO_CAT);
                replacement.writeSymbol(session.program().getSymbolTable(), site.address(), space,
                    session.program().getDataTypeManager(), false);
                cleanup(previous);
                Saved saved = findSaved(site);
                if (saved == null || saved.type() == null) {
                    throw new IllegalStateException("Written call-site signature could not be read back");
                }
                after = describeSignature(saved.signature());
            }
            JsonObject result = context(site);
            result.addProperty("status", "call_signature_set");
            result.addProperty("changed", changed);
            result.add("before", before);
            result.add("after", after);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to set call-site signature: " + e.getMessage(), e);
        }
    }

    public JsonObject handleClear(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");
        try {
            Site site = resolveSite(args);
            Saved previous = findSaved(site);
            JsonElement before = describe(previous);
            removeMarker(previous);
            cleanup(previous);
            JsonObject result = context(site);
            result.addProperty("status", "call_signature_cleared");
            result.addProperty("changed", previous != null);
            result.add("before", before);
            result.add("after", JsonNull.INSTANCE);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to clear call-site signature: " + e.getMessage(), e);
        }
    }

    private Site resolveSite(JsonObject args) throws CancelledException {
        String target = required(args, "target");
        Function caller = functions.findFunctionByNameOrAddress(target);
        if (caller == null) throw new IllegalArgumentException(functions.buildFunctionTargetHint(target));
        // Never follow a caller thunk: the override belongs to its own namespace.
        Address address = AddressCodec.parse(session.program().getAddressFactory(), required(args, "at"));
        Instruction instruction = session.program().getListing().getInstructionAt(address);
        int callCount = 0;
        String callKind = null;
        if (instruction != null) {
            for (PcodeOp operation : InstructionFlow.effectivePcode(instruction)) {
                session.monitor().checkCancelled();
                if (operation.getOpcode() == PcodeOp.CALL || operation.getOpcode() == PcodeOp.CALLIND) {
                    ++callCount;
                    callKind = operation.getOpcode() == PcodeOp.CALL ? "direct" : "indirect";
                }
            }
        }
        return new Site(caller, address, instruction, callCount, callCount == 1 ? callKind : null);
    }

    private Saved findSaved(Site site) throws CancelledException {
        Namespace space = HighFunction.findOverrideSpace(site.caller());
        if (space == null) return null;
        Saved saved = null;
        for (Symbol symbol : session.program().getSymbolTable().getSymbols(site.address())) {
            session.monitor().checkCancelled();
            if (symbol.getSymbolType() != SymbolType.LABEL || !symbol.getName().startsWith("prt_")
                    || !space.equals(symbol.getParentNamespace())) continue;
            if (saved != null) {
                throw new IllegalStateException("Multiple saved call-site overrides exist at "
                    + AddressCodec.format(site.address()) + " in " + site.caller().getName());
            }
            saved = new Saved(symbol, HighFunctionDBUtil.readOverride(symbol));
        }
        return saved;
    }

    private void removeMarker(Saved saved) throws CancelledException {
        if (saved == null) return;
        session.monitor().checkCancelled();
        if (saved.symbol().hasReferences()) {
            throw new IllegalArgumentException("Saved call-site override marker has references; "
                + "remove those references before replacing or clearing it");
        }
        if (!saved.symbol().delete()) throw new IllegalStateException("Ghidra refused to delete the override marker");
    }

    private void cleanup(Saved saved) throws CancelledException {
        if (saved == null || saved.type() == null) return;
        session.monitor().checkCancelled();
        // Cleanup scans all override symbols before deleting their shared type.
        saved.type().cleanupUnusedOverride();
    }

    private JsonObject context(Site site) {
        JsonObject result = new JsonObject();
        result.addProperty("function", site.caller().getName());
        result.addProperty("address", AddressCodec.format(site.caller().getEntryPoint()));
        result.addProperty("call_site", AddressCodec.format(site.address()));
        result.addProperty("in_body", site.caller().getBody().contains(site.address()));
        result.addProperty("instruction_exists", site.instruction() != null);
        result.addProperty("call_count", site.callCount());
        result.addProperty("call_kind", site.callKind());
        return result;
    }

    private static JsonElement describe(Saved saved) {
        return saved == null || saved.type() == null ? JsonNull.INSTANCE : describeSignature(saved.signature());
    }

    private static JsonObject describeSignature(FunctionSignature signature) {
        JsonObject result = new JsonObject();
        result.addProperty("calling_convention", signature.getCallingConventionName());
        result.addProperty("variadic", signature.hasVarArgs());
        result.addProperty("no_return", signature.hasNoReturn());
        result.add("return", describeType(signature.getReturnType()));
        JsonArray parameters = new JsonArray();
        for (ParameterDefinition parameter : signature.getArguments()) {
            JsonObject row = describeType(parameter.getDataType());
            row.addProperty("ordinal", parameter.getOrdinal());
            row.addProperty("name", parameter.getName());
            parameters.add(row);
        }
        result.add("params", parameters);
        return result;
    }

    private static JsonObject describeType(DataType type) {
        JsonObject result = new JsonObject();
        result.addProperty("type", type.getName());
        result.addProperty("type_path", type.getPathName());
        result.addProperty("size", type.getLength());
        return result;
    }

    private static String required(JsonObject args, String name) {
        String value = getArgString(args, name);
        if (value == null || value.isBlank()) throw new IllegalArgumentException(name + " required");
        return value;
    }
}
