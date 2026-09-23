package ghidracli.function;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.FunctionTag;
import ghidra.program.model.listing.FunctionTagManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.SourceType;
import ghidracli.listing.InstructionListing;
import ghidracli.query.AddressCodec;
import ghidracli.query.AddressResolver;
import ghidracli.query.ListQuery;
import ghidracli.session.ProgramSession;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static ghidracli.protocol.JsonProtocol.errorResult;
import static ghidracli.protocol.JsonProtocol.getArgBool;
import static ghidracli.protocol.JsonProtocol.getArgString;
import static ghidracli.protocol.JsonProtocol.getArgStringArray;

public final class FunctionCommands {
    private final ProgramSession session;
    private final AddressResolver addressResolver;
    private final FunctionQueries functionQueries;
    private final InstructionListing instructions;

    public FunctionCommands(ProgramSession session, AddressResolver addressResolver,
            FunctionQueries functionQueries, InstructionListing instructions) {
        this.session = session;
        this.addressResolver = addressResolver;
        this.functionQueries = functionQueries;
        this.instructions = instructions;
    }

    public JsonObject handleFunctionDisasm(JsonObject args) throws Exception {
        if (session.program() == null) return errorResult("No program loaded");
        String target = getArgString(args, "target");
        if (target == null || target.isEmpty()) return errorResult("Function target required");
        Function function = functionQueries.findFunctionByNameOrAddress(target);
        if (function == null) return errorResult(functionQueries.buildFunctionTargetHint(target));
        return instructions.instructionsIn(function.getBody(), args);
    }

    public JsonObject handleListFunctions(JsonObject args) throws ghidra.util.exception.CancelledException {
        if (session.program() == null) {
            return errorResult("No program loaded");
        }

        ListQuery query = new ListQuery(session, args);
        String[] tagFilterNames = getArgStringArray(args, "tags");
        boolean untagged = getArgBool(args, "untagged", false);

        FunctionManager fm = session.program().getFunctionManager();

        // Resolve tag filter up front: unknown tag is an error, not an empty result
        // (a typo must not read as "no matches").
        Set<FunctionTag> requiredTags = new HashSet<>();
        if (tagFilterNames.length > 0) {
            FunctionTagManager tm = fm.getFunctionTagManager();
            for (String tagName : tagFilterNames) {
                FunctionTag tag = tm.getFunctionTag(tagName);
                if (tag == null) return errorResult(TagSupport.tagNotFoundError(tagName, tm));
                requiredTags.add(tag);
            }
        }

        JsonArray functions = new JsonArray();

        FunctionIterator iter = fm.getFunctions(true);
        while (iter.hasNext()) {
            if (query.isFull()) break;

            Function func = iter.next();
            String name = func.getName();

            if (!requiredTags.isEmpty() && !func.getTags().containsAll(requiredTags)) {
                continue;
            }
            if (untagged && !func.getTags().isEmpty()) {
                continue;
            }

            if (!query.include(name)) continue;

            functions.add(functionQueries.functionToJson(func));
            query.record();
        }

        JsonObject result = new JsonObject();
        result.add("functions", functions);
        result.addProperty("count", functions.size());
        return result;
    }

    public JsonObject handleGetFunction(JsonObject args) throws ghidra.util.exception.CancelledException {
        if (session.program() == null) return errorResult("No program loaded");

        String target = getArgString(args, "address");
        if (target == null || target.isEmpty()) {
            return errorResult("Function target required");
        }

        Function func = functionQueries.findFunctionByNameOrAddress(target);
        if (func == null) {
            return errorResult(functionQueries.buildFunctionTargetHint(target));
        }
        JsonObject result = functionQueries.functionDetailToJson(func);
        if (getArgBool(args, "with_signature", false)) {
            result.add("signature_details", functionQueries.signatureDetailsToJson(func));
        }
        if (getArgBool(args, "with_frame", false)) {
            result.add("frame_details", functionQueries.frameDetailsToJson(func));
        }
        return result;
    }

    public JsonObject handleRenameFunction(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String oldTarget = getArgString(args, "old_name");
        String newName = getArgString(args, "new_name");
        String addressArg = getArgString(args, "address");
        if (oldTarget == null || newName == null || oldTarget.isEmpty() || newName.isEmpty()) {
            return errorResult("old_name and new_name required");
        }

        try {
            Function func;
            if (addressArg != null && !addressArg.isEmpty()) {
                // Scope the rename to the function whose entry point is exactly
                // this address, rather than resolving old_name program-wide --
                // Ghidra reuses auto-generated names (caseD_XX, LAB_XXXX, ...)
                // across unrelated addresses.
                Address addr = addressResolver.parseAddress(addressArg);
                if (addr == null) {
                    return errorResult("Invalid address: " + addressArg);
                }
                func = session.program().getFunctionManager().getFunctionAt(addr);
                if (func == null) {
                    return errorResult("No function at address " + addressArg);
                }
                if (!func.getName().equals(oldTarget)) {
                    return errorResult("Function at address " + addressArg + " is named '"
                        + func.getName() + "', not '" + oldTarget + "'");
                }
            } else {
                func = functionQueries.findFunctionByNameOrAddress(oldTarget);
                if (func == null) {
                    return errorResult(functionQueries.buildFunctionTargetHint(oldTarget));
                }
            }

            String oldName = func.getName();
            func.setName(newName, SourceType.USER_DEFINED);

            JsonObject result = new JsonObject();
            result.addProperty("status", "renamed");
            result.addProperty("old_name", oldName);
            result.addProperty("new_name", newName);
            result.addProperty("address", AddressCodec.format(func.getEntryPoint()));
            return result;
        } catch (Exception e) {
            return errorResult("Failed to rename function: " + e.getMessage());
        }
    }

    public JsonObject handleCreateFunction(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String target = getArgString(args, "address");
        String requestedName = getArgString(args, "name");
        if (target == null || target.isEmpty()) {
            return errorResult("Function target required");
        }

        try {
            Address addr = addressResolver.resolveAddress(target);
            if (addr == null) {
                return errorResult("Invalid function target: " + target
                    + ". Expected an exact symbol name or a 0x-prefixed address.");
            }

            FunctionManager fm = session.program().getFunctionManager();
            Function owner = fm.getFunctionContaining(addr);
            if (owner != null) {
    /** Structured "already claimed" error: who owns the address, so callers can decide without a follow-up lookup. */
                return functionAlreadyExistsError(addr, owner);
            }

            String functionName = (requestedName == null || requestedName.isEmpty())
                ? ("FUN_" + addr.toString().replace(":", ""))
                : requestedName;

            Listing listing = session.program().getListing();
            boolean autoDisassembled = false;

            // The most common reason createFunction rejects an address: no
            // instruction has been disassembled there yet (static auto-analysis
            // never reached it, e.g. a computed-jump table target). Disassemble
            // first rather than making the caller do it via a separate command.
            if (listing.getInstructionAt(addr) == null) {
                autoDisassembled = session.disassemble(addr);
                session.monitor().checkCancelled();
            }

            Function created;
            try {
                // FunctionManager.createFunction(..., body=null, ...) does not compute a
                // body by following flow from the entry point -- for many perfectly valid
                // entry points (notably ARM/Thumb vtable targets never reached by static
                // auto-analysis) it deterministically rejects the address with "Function
                // body must contain the entrypoint". CreateFunctionCmd is what
                // GhidraScript.createFunction()/the UI's "Create Function" action use: it
                // follows flow from the entry point to compute a correct body first.
                ghidra.app.cmd.function.CreateFunctionCmd cmd =
                    new ghidra.app.cmd.function.CreateFunctionCmd(
                        functionName, addr, null, SourceType.USER_DEFINED);
                boolean ok = cmd.applyTo(session.program(), session.monitor());
                session.monitor().checkCancelled();
                if (!ok) {
                    // Check likely causes (no instruction landed, a shared-code tail
                    // jump, or a code-unit boundary) to retain useful failure detail.
                    return diagnoseCreateFunctionFailure(addr, autoDisassembled, cmd.getStatusMsg());
                }
                created = fm.getFunctionAt(addr);
            } catch (Exception e) {
                // CreateFunctionCmd rejects some addresses by throwing rather than
                // returning false -- run it through the same diagnosis either way instead
                // of losing the detail to the generic catch below.
                return diagnoseCreateFunctionFailure(addr, autoDisassembled, e.getMessage());
            }
            if (created == null) {
                return diagnoseCreateFunctionFailure(addr, autoDisassembled, null);
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "created");
            result.addProperty("name", created.getName());
            result.addProperty("address", AddressCodec.format(created.getEntryPoint()));
            if (autoDisassembled) result.addProperty("auto_disassembled", true);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to create function: " + e.getMessage());
        }
    }

    private JsonObject functionAlreadyExistsError(Address addr, Function owner) {
        JsonObject detail = new JsonObject();
        detail.addProperty("name", owner.getName());
        detail.addProperty("entry_point", AddressCodec.format(owner.getEntryPoint()));
        detail.addProperty("size", owner.getBody().getNumAddresses());
        JsonObject err = errorResult("Function already exists at " + AddressCodec.format(addr)
            + ": address is inside " + owner.getName() + "@" + AddressCodec.format(owner.getEntryPoint())
            + " (size " + owner.getBody().getNumAddresses() + " bytes)");
        err.add("detail", detail);
        return err;
    }

    private JsonObject diagnoseCreateFunctionFailure(Address addr, boolean autoDisassembled, String thrownMessage) {
        Listing listing = session.program().getListing();
        List<String> reasons = new ArrayList<>();
        JsonObject detail = new JsonObject();
        detail.addProperty("address", AddressCodec.format(addr));
        detail.addProperty("auto_disassembled_attempted", autoDisassembled);
        if (thrownMessage != null) {
            detail.addProperty("ghidra_exception", thrownMessage);
        }

        boolean hasInstruction = listing.getInstructionAt(addr) != null;
        detail.addProperty("has_instruction_at_entry", hasInstruction);
        if (!hasInstruction) {
            reasons.add("no instruction landed at entry point even after a disassemble attempt "
                + "(address may be data, mid-instruction, or in an unmapped memory block)");
        }

        Function owner = session.program().getFunctionManager().getFunctionContaining(addr);
        if (owner != null) {
            detail.addProperty("containing_function", owner.getName());
            detail.addProperty("containing_function_entry", AddressCodec.format(owner.getEntryPoint()));
            detail.addProperty("containing_function_size", owner.getBody().getNumAddresses());
            reasons.add("address is already inside existing function " + owner.getName()
                + "@" + AddressCodec.format(owner.getEntryPoint()) + " (likely shared code reached by a tail jump, "
                + "not a call) -- consider `symbol create-label` for a label instead of a new function");
        }

        CodeUnit cu = listing.getCodeUnitContaining(addr);
        if (cu != null) {
            detail.addProperty("code_unit_range", AddressCodec.format(cu.getMinAddress())
                + "-" + AddressCodec.format(cu.getMaxAddress()));
            detail.addProperty("code_unit_is_instruction", cu instanceof Instruction);
            if (!cu.getMinAddress().equals(addr)) {
                reasons.add("address " + AddressCodec.format(addr) + " is mid-code-unit, not the start of "
                    + AddressCodec.format(cu.getMinAddress()) + "-" + AddressCodec.format(cu.getMaxAddress()));
            }
        }

        if (reasons.isEmpty()) {
            reasons.add(thrownMessage != null
                ? "Ghidra rejected the entry point (" + thrownMessage + ") with no other diagnosable cause found"
                : "Ghidra's FunctionManager.createFunction returned null with no further detail "
                    + "from the API; entry point may not sit on a valid code unit boundary");
        }

        JsonObject err = errorResult("Failed to create function at " + AddressCodec.format(addr) + ": "
            + String.join("; ", reasons));
        err.add("detail", detail);
        return err;
    }

    public JsonObject handleDeleteFunction(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String target = getArgString(args, "address");
        if (target == null || target.isEmpty()) {
            return errorResult("Function target required");
        }

        try {
            FunctionManager fm = session.program().getFunctionManager();
            Function func = functionQueries.findFunctionByNameOrAddress(target);
            if (func == null) {
                return errorResult(functionQueries.buildFunctionTargetHint(target));
            }

            Address entry = func.getEntryPoint();
            String name = func.getName();
            if (!fm.removeFunction(entry)) {
                return errorResult("Failed to delete function at " + AddressCodec.format(entry));
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "deleted");
            result.addProperty("name", name);
            result.addProperty("address", AddressCodec.format(entry));
            return result;
        } catch (Exception e) {
            return errorResult("Failed to delete function: " + e.getMessage());
        }
    }
}
