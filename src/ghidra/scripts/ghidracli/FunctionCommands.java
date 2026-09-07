package ghidracli;

import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
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
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import static ghidracli.JsonProtocol.errorResult;
import static ghidracli.JsonProtocol.getArgBool;
import static ghidracli.JsonProtocol.getArgInt;
import static ghidracli.JsonProtocol.getArgString;
import static ghidracli.JsonProtocol.getArgStringArray;

final class FunctionCommands {
    private final ProgramSession session;
    private final AddressResolver addressResolver;
    private final FunctionQueries functionQueries;

    FunctionCommands(ProgramSession session, AddressResolver addressResolver, FunctionQueries functionQueries) {
        this.session = session;
        this.addressResolver = addressResolver;
        this.functionQueries = functionQueries;
    }

    JsonObject handleListFunctions(JsonObject args) {
        if (session.program() == null) {
            return errorResult("No program loaded");
        }

        int limit = getArgInt(args, "limit", 0);
        String nameFilter = getArgString(args, "filter");
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
        int count = 0;

        FunctionIterator iter = fm.getFunctions(true);
        while (iter.hasNext()) {
            if (limit > 0 && count >= limit) break;

            Function func = iter.next();
            String name = func.getName();

            if (nameFilter != null && !name.toLowerCase().contains(nameFilter.toLowerCase())) {
                continue;
            }
            if (!requiredTags.isEmpty() && !func.getTags().containsAll(requiredTags)) {
                continue;
            }
            if (untagged && !func.getTags().isEmpty()) {
                continue;
            }

            JsonObject funcData = new JsonObject();
            funcData.addProperty("name", name);
            funcData.addProperty("address", func.getEntryPoint().toString());
            funcData.addProperty("size", func.getBody().getNumAddresses());
            funcData.addProperty("entry_point", func.getEntryPoint().toString());
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

            functions.add(functionQueries.functionToJson(func));
            count++;
        }

        JsonObject result = new JsonObject();
        result.add("functions", functions);
        result.addProperty("count", functions.size());
        return result;
    }

    JsonObject handleGetFunction(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String target = getArgString(args, "address");
        if (target == null || target.isEmpty()) {
            return errorResult("Function target required");
        }

        Address addr = addressResolver.resolveAddress(target);
        if (addr == null) {
            return errorResult(functionQueries.buildFunctionTargetHint(target));
        }

        Function func = session.program().getFunctionManager().getFunctionContaining(addr);
        if (func == null) {
            return errorResult("No function at target " + target + ". Try: ghidra function list --filter " + target);
        }
        return functionQueries.functionToJson(func);
    }

    JsonObject handleRenameFunction(JsonObject args) {
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
                Address addr = addressResolver.resolveAddress(addressArg);
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

            ProgramTransaction transaction = session.transaction("Rename function");
            try {
                String oldName = func.getName();
                func.setName(newName, SourceType.USER_DEFINED);
                transaction.end(true);

                JsonObject result = new JsonObject();
                result.addProperty("status", "renamed");
                result.addProperty("old_name", oldName);
                result.addProperty("new_name", newName);
                result.addProperty("address", func.getEntryPoint().toString());
                return result;
            } catch (Exception e) {
                transaction.end(true);
                throw e;
            }
        } catch (Exception e) {
            return errorResult("Failed to rename function: " + e.getMessage());
        }
    }

    JsonObject handleCreateFunction(JsonObject args) {
        if (session.program() == null) return errorResult("No program loaded");

        String target = getArgString(args, "address");
        String requestedName = getArgString(args, "name");
        if (target == null || target.isEmpty()) {
            return errorResult("Function target required");
        }

        try {
            Address addr = addressResolver.resolveAddress(target);
            if (addr == null) {
                return errorResult("Invalid function target: " + target + ". Expected address/symbol/FUN_<hex>.");
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

            ProgramTransaction transaction = session.transaction("Create function");
            try {
                // The most common reason createFunction rejects an address: no
                // instruction has been disassembled there yet (static auto-analysis
                // never reached it, e.g. a computed-jump table target). Disassemble
                // first rather than making the caller do it via a separate command.
                if (listing.getInstructionAt(addr) == null) {
                    autoDisassembled = session.disassemble(addr);
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
                    if (!ok) {
                        transaction.end(true);
    /**
     * fm.createFunction returning null carries no reason from Ghidra itself.
     * Check the likely causes ourselves (no instruction landed, address already
     * inside another function's body from a shared-code tail jump, boundary not
     * on a code unit start) so the error distinguishes them instead of
     * collapsing to one generic message.
     */
                        return diagnoseCreateFunctionFailure(addr, autoDisassembled, cmd.getStatusMsg());
                    }
                    created = fm.getFunctionAt(addr);
                } catch (Exception e) {
                    // CreateFunctionCmd rejects some addresses by throwing rather than
                    // returning false -- run it through the same diagnosis either way instead
                    // of losing the detail to the generic catch below.
                    transaction.end(true);
                    return diagnoseCreateFunctionFailure(addr, autoDisassembled, e.getMessage());
                }
                if (created == null) {
                    transaction.end(true);
                    return diagnoseCreateFunctionFailure(addr, autoDisassembled, null);
                }
                transaction.end(true);

                JsonObject result = new JsonObject();
                result.addProperty("status", "created");
                result.addProperty("name", created.getName());
                result.addProperty("address", created.getEntryPoint().toString());
                if (autoDisassembled) result.addProperty("auto_disassembled", true);
                return result;
            } catch (Exception e) {
                transaction.end(true);
                throw e;
            }
        } catch (Exception e) {
            return errorResult("Failed to create function: " + e.getMessage());
        }
    }

    private JsonObject functionAlreadyExistsError(Address addr, Function owner) {
        JsonObject detail = new JsonObject();
        detail.addProperty("name", owner.getName());
        detail.addProperty("entry_point", owner.getEntryPoint().toString());
        detail.addProperty("size", owner.getBody().getNumAddresses());
        JsonObject err = errorResult("Function already exists at " + addr.toString()
            + ": address is inside " + owner.getName() + "@" + owner.getEntryPoint()
            + " (size " + owner.getBody().getNumAddresses() + " bytes)");
        err.add("detail", detail);
        return err;
    }

    private JsonObject diagnoseCreateFunctionFailure(Address addr, boolean autoDisassembled, String thrownMessage) {
        Listing listing = session.program().getListing();
        List<String> reasons = new ArrayList<>();
        JsonObject detail = new JsonObject();
        detail.addProperty("address", addr.toString());
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
            detail.addProperty("containing_function_entry", owner.getEntryPoint().toString());
            detail.addProperty("containing_function_size", owner.getBody().getNumAddresses());
            reasons.add("address is already inside existing function " + owner.getName()
                + "@" + owner.getEntryPoint() + " (likely shared code reached by a tail jump, "
                + "not a call) -- consider `symbol create` for a label instead of a new function");
        }

        CodeUnit cu = listing.getCodeUnitContaining(addr);
        if (cu != null) {
            detail.addProperty("code_unit_range", cu.getMinAddress() + "-" + cu.getMaxAddress());
            detail.addProperty("code_unit_is_instruction", cu instanceof Instruction);
            if (!cu.getMinAddress().equals(addr)) {
                reasons.add("address " + addr + " is mid-code-unit, not the start of "
                    + cu.getMinAddress() + "-" + cu.getMaxAddress());
            }
        }

        if (reasons.isEmpty()) {
            reasons.add(thrownMessage != null
                ? "Ghidra rejected the entry point (" + thrownMessage + ") with no other diagnosable cause found"
                : "Ghidra's FunctionManager.createFunction returned null with no further detail "
                    + "from the API; entry point may not sit on a valid code unit boundary");
        }

        JsonObject err = errorResult("Failed to create function at " + addr.toString() + ": "
            + String.join("; ", reasons));
        err.add("detail", detail);
        return err;
    }

    JsonObject handleDeleteFunction(JsonObject args) {
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
            ProgramTransaction transaction = session.transaction("Delete function");
            try {
                fm.removeFunction(entry);
                transaction.end(true);
            } catch (Exception e) {
                transaction.end(true);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "deleted");
            result.addProperty("name", name);
            result.addProperty("address", entry.toString());
            return result;
        } catch (Exception e) {
            return errorResult("Failed to delete function: " + e.getMessage());
        }
    }
}
